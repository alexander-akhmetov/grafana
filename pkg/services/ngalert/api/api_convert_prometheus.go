package api

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	prommodel "github.com/prometheus/common/model"

	"github.com/grafana/grafana/pkg/api/response"
	"github.com/grafana/grafana/pkg/infra/log"
	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
	"github.com/grafana/grafana/pkg/services/dashboards"
	"github.com/grafana/grafana/pkg/services/datasources"
	"github.com/grafana/grafana/pkg/services/folder"
	apimodels "github.com/grafana/grafana/pkg/services/ngalert/api/tooling/definitions"
	"github.com/grafana/grafana/pkg/services/ngalert/models"
	"github.com/grafana/grafana/pkg/services/ngalert/prom"
	"github.com/grafana/grafana/pkg/services/ngalert/provisioning"
	"github.com/grafana/grafana/pkg/util"
)

const (
	datasourceUIDHeader        = "X-Datasource-UID"
	recordingRulesPausedHeader = "X-Recording-Rules-Paused"
	alertRulesPausedHeader     = "X-Alert-Rules-Paused"
)

type ConvertPrometheusSrv struct {
	logger           log.Logger
	ruleStore        RuleStore
	datasourceCache  datasources.CacheService
	alertRuleService *provisioning.AlertRuleService
}

func NewConvertPrometheusSrv(logger log.Logger, ruleStore RuleStore, datasourceCache datasources.CacheService, alertRuleService *provisioning.AlertRuleService) *ConvertPrometheusSrv {
	return &ConvertPrometheusSrv{
		logger:           logger,
		ruleStore:        ruleStore,
		datasourceCache:  datasourceCache,
		alertRuleService: alertRuleService,
	}
}

func (srv *ConvertPrometheusSrv) RouteConvertPrometheusGetRules(c *contextmodel.ReqContext) response.Response {
	listRulesQuery := &models.ListAlertRulesQuery{ImportedPrometheusRule: util.Pointer(true)}
	groupsWithFolders, err := srv.alertRuleService.GetAlertGroupsWithFolderFullpath(c.Req.Context(), c.SignedInUser, nil, listRulesQuery)
	if err != nil {
		return errorToResponse(err)
	}

	result := map[string][]apimodels.PrometheusRuleGroup{}

	for _, group := range groupsWithFolders {
		rules := make([]*models.AlertRule, len(group.Rules))
		for i, r := range group.Rules {
			rules[i] = &r
		}
		promGroup, err := grafanaRuleGroupToPrometheus(group.Title, rules)
		if err != nil {
			return errorToResponse(err)
		}

		result[group.FolderFullpath] = append(result[group.FolderFullpath], promGroup)
	}

	return response.YAML(http.StatusOK, result)
}

func (srv *ConvertPrometheusSrv) RouteConvertPrometheusDeleteNamespace(c *contextmodel.ReqContext, namespaceTitle string) response.Response {
	logger := srv.logger.FromContext(c.Req.Context())

	logger.Debug("Searching for the namespace", "fullpath", namespaceTitle)

	folder, err := srv.ruleStore.GetNamespaceByFullpath(c.Req.Context(), namespaceTitle, c.SignedInUser.GetOrgID(), c.SignedInUser)
	if err != nil {
		return toNamespaceErrorResponse(err)
	}

	logger.Debug("Found namespace", "namespace", folder.UID)

	// A folder can contain multiple groups, and some of them can be created by the user in the UI.
	// We don't want to delete them, so we filter out only the rules with the provenance "importedPrometheus".
	listRulesQuery := &models.ListAlertRulesQuery{ImportedPrometheusRule: util.Pointer(true)}
	srv.alertRuleService.DeleteAllGroupsInNamespace(c.Req.Context(), c.SignedInUser, folder.UID, models.ProvenanceImportedPrometheus, listRulesQuery)

	return response.JSON(http.StatusAccepted, apimodels.ConvertPrometheusResponse{Status: "success"})
}

func (srv *ConvertPrometheusSrv) RouteConvertPrometheusDeleteRuleGroup(c *contextmodel.ReqContext, namespaceTitle string, group string) response.Response {
	logger := srv.logger.FromContext(c.Req.Context())

	logger.Debug("Searching for the namespace", "fullpath", namespaceTitle)

	folder, err := srv.ruleStore.GetNamespaceByFullpath(c.Req.Context(), namespaceTitle, c.SignedInUser.GetOrgID(), c.SignedInUser)
	if err != nil {
		return toNamespaceErrorResponse(err)
	}

	logger.Debug("Found namespace", "namespace", folder.UID)

	err = srv.alertRuleService.DeleteRuleGroup(c.Req.Context(), c.SignedInUser, folder.UID, group, models.ProvenanceImportedPrometheus)
	if err != nil {
		return errorToResponse(err)
	}

	return response.JSON(http.StatusAccepted, apimodels.ConvertPrometheusResponse{Status: "success"})
}

func (srv *ConvertPrometheusSrv) RouteConvertPrometheusGetNamespace(c *contextmodel.ReqContext, namespaceTitle string) response.Response {
	logger := srv.logger.FromContext(c.Req.Context())

	logger.Debug("Searching for the namespace", "fullpath", namespaceTitle)

	namespace, err := srv.ruleStore.GetNamespaceByFullpath(c.Req.Context(), namespaceTitle, c.SignedInUser.GetOrgID(), c.SignedInUser)
	if err != nil {
		return toNamespaceErrorResponse(err)
	}
	if errors.Is(err, dashboards.ErrFolderAccessDenied) {
		// If there is no such folder, GetNamespaceByUID returns ErrFolderAccessDenied.
		// We should return 404 in this case, otherwise mimirtool does not work correctly.
		return response.Empty(http.StatusNotFound)
	}

	listRulesQuery := &models.ListAlertRulesQuery{
		NamespaceUIDs:          []string{namespace.UID},
		ImportedPrometheusRule: util.Pointer(true),
	}

	rules, _, err := srv.alertRuleService.GetAlertRules(c.Req.Context(), c.SignedInUser, listRulesQuery)
	if err != nil {
		return errorToResponse(err)
	}
	groups := models.GroupByAlertRuleGroupKey(rules)

	promNamespace := map[string][]apimodels.PrometheusRuleGroup{
		namespace.Fullpath: make([]apimodels.PrometheusRuleGroup, 0, len(groups)),
	}

	for groupKey, rules := range groups {
		promGroup, err := grafanaRuleGroupToPrometheus(groupKey.RuleGroup, rules)
		if err != nil {
			return errorToResponse(err)
		}
		promNamespace[namespace.Fullpath] = append(promNamespace[namespace.Fullpath], promGroup)
	}

	return response.YAML(http.StatusOK, promNamespace)
}

func (srv *ConvertPrometheusSrv) RouteConvertPrometheusGetRuleGroup(c *contextmodel.ReqContext, namespaceTitle string, group string) response.Response {
	logger := srv.logger.FromContext(c.Req.Context())

	logger.Debug("Searching for the namespace", "fullpath", namespaceTitle)

	namespace, err := srv.ruleStore.GetNamespaceByFullpath(c.Req.Context(), namespaceTitle, c.SignedInUser.GetOrgID(), c.SignedInUser)
	if err != nil {
		return toNamespaceErrorResponse(err)
	}
	if errors.Is(err, dashboards.ErrFolderAccessDenied) {
		// If there is no such folder, GetNamespaceByUID returns ErrFolderAccessDenied.
		// We should return 404 in this case, otherwise mimirtool does not work correctly.
		return response.Empty(http.StatusNotFound)
	}

	finalRuleGroup, err := getRulesGroupParam(c, group)
	if err != nil {
		return ErrResp(http.StatusBadRequest, err, "")
	}

	logger.Debug("Getting rules for the rule group", "rule_group", finalRuleGroup, "namespace_uid", namespace.UID)

	listRulesQuery := &models.ListAlertRulesQuery{
		ImportedPrometheusRule: util.Pointer(true),
	}
	ruleGroup, err := srv.alertRuleService.GetRuleGroup(c.Req.Context(), c.SignedInUser, namespace.UID, finalRuleGroup, listRulesQuery)
	if err != nil {
		return errorToResponse(err)
	}

	rules := make([]*models.AlertRule, len(ruleGroup.Rules))
	for i, r := range ruleGroup.Rules {
		rules[i] = &r
	}
	promGroup, err := grafanaRuleGroupToPrometheus(group, rules)

	logger.Debug("Found rules in Prometheus format", "rule_group", group, "rules", len(promGroup.Rules))

	return response.YAML(http.StatusOK, promGroup)
}

func grafanaRuleGroupToPrometheus(group string, rules []*models.AlertRule) (apimodels.PrometheusRuleGroup, error) {
	if len(rules) == 0 {
		return apimodels.PrometheusRuleGroup{}, nil
	}

	interval := time.Duration(rules[0].IntervalSeconds) * time.Second
	promGroup := apimodels.PrometheusRuleGroup{
		Name:     group,
		Interval: prommodel.Duration(interval),
		Rules:    make([]apimodels.PrometheusRule, len(rules)),
	}

	for i, rule := range rules {
		r, err := grafanaRuleToPrometheus(rule)
		if err != nil {
			return promGroup, errors.New("failed to convert rule")
		}
		promGroup.Rules[i] = r
	}

	return promGroup, nil
}

func grafanaRuleToPrometheus(rule *models.AlertRule) (apimodels.PrometheusRule, error) {
	var r apimodels.PrometheusRule
	if err := yaml.Unmarshal([]byte(rule.Metadata.PrometheusStyleRule.OriginalRuleDefinition), &r); err != nil {
		return r, fmt.Errorf("failed to unmarshal rule with UID %s", rule.UID)
	}

	return r, nil
}

func (srv *ConvertPrometheusSrv) RouteConvertPrometheusPostRuleGroup(c *contextmodel.ReqContext, namespaceTitle string, promGroup apimodels.PrometheusRuleGroup) response.Response {
	logger := srv.logger.FromContext(c.Req.Context())

	ns, errResp := srv.getOrCreateNamespace(c, namespaceTitle, logger)
	if errResp != nil {
		return errResp
	}

	rules := make([]prom.PrometheusRule, len(promGroup.Rules))
	for i, r := range promGroup.Rules {
		rules[i] = prom.PrometheusRule{
			Alert:         r.Alert,
			Expr:          r.Expr,
			For:           r.For,
			KeepFiringFor: r.KeepFiringFor,
			Labels:        r.Labels,
			Annotations:   r.Annotations,
			Record:        r.Record,
		}
	}

	group := prom.PrometheusRuleGroup{
		Name:     promGroup.Name,
		Interval: promGroup.Interval,
		Rules:    rules,
	}

	grafanaGroup, err := srv.convertToGrafanaRuleGroup(c, ns.UID, group, logger)
	if err != nil {
		return errorToResponse(err)
	}

	srv.alertRuleService.ReplaceRuleGroup(c.Req.Context(), c.SignedInUser, *grafanaGroup, models.ProvenanceImportedPrometheus)

	return response.JSON(http.StatusAccepted, map[string]string{"status": "success"})
}

func (srv *ConvertPrometheusSrv) getOrCreateNamespace(c *contextmodel.ReqContext, title string, logger log.Logger) (*folder.Folder, response.Response) {
	logger.Debug("Getting or creating a new namespace", "title", title)
	ns, err := srv.ruleStore.GetOrCreateNamespaceInRootByTitle(
		c.Req.Context(),
		title,
		c.SignedInUser.GetOrgID(),
		c.SignedInUser,
	)
	if err != nil {
		logger.Error("Failed to create a new namespace", "error", err)
		return nil, toNamespaceErrorResponse(err)
	}
	return ns, nil
}

func (srv *ConvertPrometheusSrv) convertToGrafanaRuleGroup(c *contextmodel.ReqContext, namespaceUID string, group prom.PrometheusRuleGroup, logger log.Logger) (*models.AlertRuleGroup, error) {
	logger.Debug("Converting Prometheus rules to Grafana rules",
		"group", group.Name,
		"namespace_uid", namespaceUID,
		"rules", len(group.Rules),
	)

	datasourceUID := strings.TrimSpace(c.Req.Header.Get(datasourceUIDHeader))
	ds, err := srv.datasourceCache.GetDatasourceByUID(c.Req.Context(), datasourceUID, c.SignedInUser, c.SkipDSCache)
	if err != nil {
		logger.Error("Failed to get datasource", "error", err)
		return nil, err
	}

	converter, err := prom.NewConverter(
		prom.Config{
			DatasourceUID:  ds.UID,
			DatasourceType: ds.Type,
			RecordingRules: prom.RulesConfig{
				IsPaused: c.QueryBool(c.Req.Header.Get(recordingRulesPausedHeader)),
			},
			AlertRules: prom.RulesConfig{
				IsPaused: c.QueryBool(c.Req.Header.Get(alertRulesPausedHeader)),
			},
		},
	)
	if err != nil {
		logger.Error("Failed to create Prometheus converter", "error", err)
		return nil, err
	}

	grafanaGroup, err := converter.PrometheusRulesToGrafana(c.SignedInUser.GetOrgID(), namespaceUID, group)
	if err != nil {
		logger.Error("Failed to convert Prometheus rules to Grafana rules", "error", err)
		return nil, err
	}

	return grafanaGroup, nil
}
