package alerting

import (
	"testing"
	"time"

	prommodel "github.com/prometheus/common/model"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/services/datasources"
	apimodels "github.com/grafana/grafana/pkg/services/ngalert/api/tooling/definitions"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/tests/testinfra"
)

func TestIntegrationConvertPrometheusEndpoints(t *testing.T) {
	testinfra.SQLiteIntegrationTest(t)

	// Setup Grafana and its Database
	dir, path := testinfra.CreateGrafDir(t, testinfra.GrafanaOpts{
		DisableLegacyAlerting: true,
		EnableUnifiedAlerting: true,
		DisableAnonymous:      true,
		AppModeProduction:     true,
		EnableFeatureToggles:  []string{"alertingConversionAPI"},
	})

	grafanaListedAddr, env := testinfra.StartGrafanaEnv(t, dir, path)

	// Create a user to make authenticated requests
	createUser(t, env.SQLStore, env.Cfg, user.CreateUserCommand{
		DefaultOrgRole: string(org.RoleAdmin),
		Password:       "password",
		Login:          "admin",
	})

	apiClient := newAlertingApiClient(grafanaListedAddr, "admin", "password")

	namespace := "test-namespace"

	durationPtr := func(d time.Duration) *prommodel.Duration {
		dur := prommodel.Duration(d)
		return &dur
	}

	promGroup1 := apimodels.PrometheusRuleGroup{
		Name:     "test-group-1",
		Interval: prommodel.Duration(60 * time.Second),
		Rules: []apimodels.PrometheusRule{
			// Recording rule
			{
				Record: "test:requests:rate5m",
				Expr:   "sum(rate(test_requests_total[5m])) by (job)",
				Labels: map[string]string{
					"env":  "prod",
					"team": "infra",
				},
			},
			// Two alerting rules
			{
				Alert: "HighMemoryUsage",
				Expr:  "process_memory_usage > 80",
				For:   durationPtr(5 * time.Minute),
				Labels: map[string]string{
					"severity": "warning",
					"team":     "alerting",
				},
				Annotations: map[string]string{
					"annotation-1": "value-1",
					"annotation-2": "value-2",
				},
			},
			{
				Alert: "ServiceDown",
				Expr:  "up == 0",
				For:   durationPtr(2 * time.Minute),
				Labels: map[string]string{
					"severity": "critical",
				},
				Annotations: map[string]string{
					"annotation-1": "value-1",
				},
			},
		},
	}

	promGroup2 := apimodels.PrometheusRuleGroup{
		Name:     "test-group-2",
		Interval: prommodel.Duration(60 * time.Second),
		Rules: []apimodels.PrometheusRule{
			{
				Alert: "HighDiskUsage",
				Expr:  "disk_usage > 80",
				For:   durationPtr(2 * time.Minute),
				Labels: map[string]string{
					"severity": "low",
					"team":     "alerting",
				},
				Annotations: map[string]string{
					"annotation-5": "value-5",
				},
			},
		},
	}

	ds := apiClient.CreateDatasource(t, datasources.DS_PROMETHEUS)

	t.Run("create two rule groups and get them back", func(t *testing.T) {
		apiClient.ConvertPrometheusPostRuleGroup(t, namespace, ds.Body.Datasource.UID, promGroup1)
		apiClient.ConvertPrometheusPostRuleGroup(t, namespace, ds.Body.Datasource.UID, promGroup2)

		namespaces := apiClient.ConvertPrometheusGetAllRules(t)

		require.Len(t, namespaces, 1)
		require.NotNil(t, namespaces[namespace])

		groups := namespaces[namespace]
		require.Len(t, groups, 2)
		require.Equal(t, promGroup1, groups[0])
		require.Equal(t, promGroup2, groups[1])
	})

	t.Run("DELETE rule group", func(t *testing.T) {
		// Create two rule group in the same namespace
		apiClient.ConvertPrometheusPostRuleGroup(t, namespace, ds.Body.Datasource.UID, promGroup1)
		apiClient.ConvertPrometheusPostRuleGroup(t, namespace, ds.Body.Datasource.UID, promGroup2)

		// Delete one of the rule groups
		apiClient.ConvertPrometheusDeleteRuleGroup(t, namespace, promGroup1.Name)

		// The remaining rule group should be the one we didn't delete
		namespaces := apiClient.ConvertPrometheusGetAllRules(t)
		require.NotNil(t, namespaces[namespace])
		groups := namespaces[namespace]
		require.Len(t, groups, 1)
		require.Equal(t, promGroup2, groups[0])
	})

	t.Run("DELETE namespace", func(t *testing.T) {
		// Create the rule group in the namespace
		apiClient.ConvertPrometheusPostRuleGroup(t, namespace, ds.Body.Datasource.UID, promGroup1)

		// And now delete the namespace
		apiClient.ConvertPrometheusDeleteNamespace(t, namespace)

		namespaces := apiClient.ConvertPrometheusGetAllRules(t)
		require.Len(t, namespaces, 0)
	})
}
