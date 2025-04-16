package metrics_writer

import (
	"context"
	"errors"
	"math"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/grafana/dataplane/sdata/numeric"
	"github.com/grafana/grafana-plugin-sdk-go/data"
	promValue "github.com/prometheus/prometheus/model/value"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/services/ngalert/eval"
	"github.com/grafana/grafana/pkg/services/ngalert/models"
	"github.com/grafana/grafana/pkg/services/ngalert/state"
	"github.com/grafana/grafana/pkg/services/ngalert/state/metrics_writer/model"
)

type fakeRemoteWriter struct {
	mock.Mock
}

func (f *fakeRemoteWriter) WriteDatasource(ctx context.Context, dsUID string, name string, t time.Time, frames data.Frames, orgID int64, extraLabels map[string]string) error {
	args := f.Called(ctx, dsUID, name, t, frames, orgID, extraLabels)
	return args.Error(0)
}

func TestNewWriter(t *testing.T) {
	cfg := Config{DatasourceUID: "test-ds-uid"}
	fakeWriter := new(fakeRemoteWriter)
	logger := log.NewNopLogger()

	metricsWriter := NewWriter(cfg, fakeWriter, logger)

	require.NotNil(t, metricsWriter)
	require.Equal(t, cfg.DatasourceUID, metricsWriter.cfg.DatasourceUID)
	require.Equal(t, fakeWriter, metricsWriter.promWriter)
	require.Equal(t, logger, metricsWriter.logger)
}

func createExpectedFrame(t *testing.T, ruleUID, ruleName, promState, grafanaState string, instanceLabels data.Labels, value float64) *data.Frame {
	t.Helper()

	labels := instanceLabels.Copy()
	labels[alertRuleUIDLabel] = ruleUID
	labels[alertNameLabel] = ruleName
	labels[alertStateLabel] = promState
	labels[grafanaAlertStateLabel] = grafanaState

	valueField := data.NewField("", labels, []float64{value})

	frame := data.NewFrame(alertMetricName, valueField)
	frame.SetMeta(&data.FrameMeta{
		Type:        data.FrameTypeNumericMulti,
		TypeVersion: numeric.MultiFrameVersionLatest,
	})
	return frame
}

func TestAlertStateMetricsWriter_Write(t *testing.T) {
	cfg := Config{DatasourceUID: "test-ds-uid"}
	logger := log.NewNopLogger()
	ctx := context.Background()
	orgID := int64(1)
	now := time.Now()

	testCases := []struct {
		name           string
		ruleMeta       model.RuleMeta
		states         state.StateTransitions
		expectedErr    error
		expectedFrames data.Frames
	}{
		{
			name:     "No states",
			ruleMeta: model.RuleMeta{Title: "Test Rule No States"},
			states:   state.StateTransitions{},
		},
		{
			name:     "Ignored states only (Normal, Error)",
			ruleMeta: model.RuleMeta{Title: "test rule"},
			states: state.StateTransitions{
				{State: &state.State{AlertRuleUID: "rule-uid-normal", OrgID: orgID, Labels: data.Labels{"label1": "value1"}, State: eval.Normal, LastEvaluationTime: now}},
				{State: &state.State{AlertRuleUID: "rule-uid-error", OrgID: orgID, Labels: data.Labels{"label2": "value2"}, State: eval.Error, LastEvaluationTime: now}},
			},
		},
		{
			name:     "Single Alerting state",
			ruleMeta: model.RuleMeta{Title: "test rule"},
			states: state.StateTransitions{
				{State: &state.State{AlertRuleUID: "rule-uid-alerting", OrgID: orgID, Labels: data.Labels{"instance": "server1"}, State: eval.Alerting, LastEvaluationTime: now}},
			},
			expectedFrames: data.Frames{
				createExpectedFrame(t, "rule-uid-alerting", "test rule", "firing", "alerting", data.Labels{"instance": "server1"}, 1.0),
			},
		},
		{
			name:     "Mixed states (Normal, Pending, Recovering)",
			ruleMeta: model.RuleMeta{Title: "test rule"},
			states: state.StateTransitions{
				{State: &state.State{AlertRuleUID: "rule-uid-normal", OrgID: orgID, Labels: data.Labels{"state": "normal"}, State: eval.Normal, LastEvaluationTime: now}},
				{State: &state.State{AlertRuleUID: "rule-uid-pending", OrgID: orgID, Labels: data.Labels{"state": "pending"}, State: eval.Pending, LastEvaluationTime: now}},
				{State: &state.State{AlertRuleUID: "rule-uid-recovering", OrgID: orgID, Labels: data.Labels{"state": "recovering"}, State: eval.Recovering, LastEvaluationTime: now}},
			},
			expectedFrames: data.Frames{
				createExpectedFrame(t, "rule-uid-pending", "test rule", "pending", "pending", data.Labels{"state": "pending"}, 1.0),
				createExpectedFrame(t, "rule-uid-recovering", "test rule", "firing", "recovering", data.Labels{"state": "recovering"}, 1.0),
			},
		},
		{
			// When transitioning from Alerting to Normal, we should write the
			// Alerting state with the special StaleNaN value.
			name:     "Alerting -> Normal transition",
			ruleMeta: model.RuleMeta{Title: "test rule"},
			states: state.StateTransitions{
				{
					State:         &state.State{AlertRuleUID: "rule-uid", OrgID: orgID, Labels: data.Labels{"instance": "server1"}, State: eval.Normal, LastEvaluationTime: now},
					PreviousState: eval.Alerting,
				},
			},
			expectedFrames: data.Frames{
				createExpectedFrame(t, "rule-uid", "test rule", "firing", "alerting", data.Labels{"instance": "server1"}, math.Float64frombits(promValue.StaleNaN)),
			},
		},
		{
			// When transitioning from Pending to Normal, we should write the
			// Alerting state with the special StaleNaN value.
			name:     "Pending -> Normal transition",
			ruleMeta: model.RuleMeta{Title: "test rule"},
			states: state.StateTransitions{
				{
					State:         &state.State{AlertRuleUID: "rule-uid", OrgID: orgID, Labels: data.Labels{"instance": "server1"}, State: eval.Normal, LastEvaluationTime: now},
					PreviousState: eval.Pending,
				},
			},
			expectedFrames: data.Frames{
				createExpectedFrame(t, "rule-uid", "test rule", "pending", "pending", data.Labels{"instance": "server1"}, math.Float64frombits(promValue.StaleNaN)),
			},
		},
		{
			// When transitioning from Recovering to Normal, we should write the
			// Alerting state with the special StaleNaN value.
			name:     "Recovering -> Normal transition",
			ruleMeta: model.RuleMeta{Title: "test rule"},
			states: state.StateTransitions{
				{
					State:         &state.State{AlertRuleUID: "rule-uid", OrgID: orgID, Labels: data.Labels{"instance": "server1"}, State: eval.Normal, LastEvaluationTime: now},
					PreviousState: eval.Recovering,
				},
			},
			expectedFrames: data.Frames{
				createExpectedFrame(t, "rule-uid", "test rule", "firing", "recovering", data.Labels{"instance": "server1"}, math.Float64frombits(promValue.StaleNaN)),
			},
		},
		{
			name:     "Remote writer error",
			ruleMeta: model.RuleMeta{Title: "test rule"},
			states: state.StateTransitions{
				{State: &state.State{AlertRuleUID: "rule-uid-err", OrgID: orgID, Labels: data.Labels{}, State: eval.Alerting, LastEvaluationTime: now}},
			},
			expectedFrames: data.Frames{
				createExpectedFrame(t, "rule-uid-err", "test rule", "firing", "alerting", data.Labels{}, 1),
			},
			expectedErr: errors.New("remote write failed"),
		},
		{
			name:     "Internal labels are skipped",
			ruleMeta: model.RuleMeta{Title: "test rule"},
			states: state.StateTransitions{
				{
					State: &state.State{
						AlertRuleUID:       "rule-uid-internal",
						OrgID:              orgID,
						Labels:             data.Labels{models.AutogeneratedRouteLabel: "ignored", "label1": "value1", "__label2": "value2"},
						State:              eval.Alerting,
						LastEvaluationTime: now,
					},
				},
			},
			expectedFrames: data.Frames{
				createExpectedFrame(t, "rule-uid-internal", "test rule", "firing", "alerting", data.Labels{"label1": "value1", "__label2": "value2"}, 1.0),
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fakeWriter := new(fakeRemoteWriter)
			metricsWriter := NewWriter(cfg, fakeWriter, logger)

			if tc.expectedFrames != nil {
				var extraLabels map[string]string
				fakeWriter.On(
					"WriteDatasource", ctx, cfg.DatasourceUID, alertMetricName, now, framesEqual(tc.expectedFrames), orgID, extraLabels,
				).Return(tc.expectedErr).Once()
			}

			errCh := metricsWriter.Write(ctx, tc.ruleMeta, tc.states)
			err, ok := <-errCh
			require.True(t, ok)

			if tc.expectedErr != nil {
				require.ErrorIs(t, err, tc.expectedErr)
			} else {
				require.Nil(t, err)
			}

			fakeWriter.AssertExpectations(t)
			if tc.expectedFrames == nil {
				fakeWriter.AssertNotCalled(t, "WriteDatasource", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
			}
		})
	}
}

// Custom comparer that treats NaN values as equal
func frameCmp(a, b *data.Frame) bool {
	opts := []cmp.Option{
		cmp.Comparer(func(x, y float64) bool {
			if math.IsNaN(x) && math.IsNaN(y) {
				return true
			}
			return x == y
		}),
		cmp.AllowUnexported(data.Frame{}, data.Field{}),
	}
	return cmp.Equal(a, b, opts...)
}

func framesEqual(want data.Frames) interface{} {
	return mock.MatchedBy(func(got data.Frames) bool {
		if len(got) != len(want) {
			return false
		}
		for i := range got {
			if !frameCmp(got[i], want[i]) {
				return false
			}
		}
		return true
	})
}
