package aegirsecurity

import (
	"fmt"
	"strings"
	"time"
)

type BudgetExhaustedError struct {
	Envelope BudgetEnvelope
}

func (e *BudgetExhaustedError) Error() string {
	return fmt.Sprintf("Budget exhausted for %s on '%s'.", e.Envelope.ControlType, e.Envelope.SubjectKey)
}

type InMemoryBudgetEnvelopeService struct {
	window time.Duration
	limits map[string]int
	state  map[string]budgetCounterState
}

type BudgetEnvelopeOptions struct {
	IdentityScanLimit           int
	ExternalLookupLimit         int
	ConnectionGraphRebuildLimit int
	WindowMS                    int
}

type budgetCounterState struct {
	windowStartedAt time.Time
	consumed        int
}

func NewInMemoryBudgetEnvelopeService(options ...BudgetEnvelopeOptions) *InMemoryBudgetEnvelopeService {
	resolved := BudgetEnvelopeOptions{
		IdentityScanLimit:           25,
		ExternalLookupLimit:         50,
		ConnectionGraphRebuildLimit: 10,
		WindowMS:                    60000,
	}
	if len(options) > 0 {
		if options[0].IdentityScanLimit != 0 {
			resolved.IdentityScanLimit = options[0].IdentityScanLimit
		}
		if options[0].ExternalLookupLimit != 0 {
			resolved.ExternalLookupLimit = options[0].ExternalLookupLimit
		}
		if options[0].ConnectionGraphRebuildLimit != 0 {
			resolved.ConnectionGraphRebuildLimit = options[0].ConnectionGraphRebuildLimit
		}
		if options[0].WindowMS != 0 {
			resolved.WindowMS = options[0].WindowMS
		}
	}

	return &InMemoryBudgetEnvelopeService{
		window: time.Duration(resolved.WindowMS) * time.Millisecond,
		limits: map[string]int{
			"IdentityScan":           resolved.IdentityScanLimit,
			"ExternalLookup":         resolved.ExternalLookupLimit,
			"ConnectionGraphRebuild": resolved.ConnectionGraphRebuildLimit,
		},
		state: make(map[string]budgetCounterState),
	}
}

func (s *InMemoryBudgetEnvelopeService) GetEnvelope(controlType, subjectKey string) BudgetEnvelope {
	key := buildBudgetKey(controlType, subjectKey)
	current, ok := s.state[key]
	if !ok {
		current = budgetCounterState{windowStartedAt: time.Now().UTC(), consumed: 0}
	}
	return s.toEnvelope(controlType, strings.TrimSpace(subjectKey), current)
}

func (s *InMemoryBudgetEnvelopeService) Consume(controlType, subjectKey string) (BudgetEnvelope, error) {
	key := buildBudgetKey(controlType, subjectKey)
	now := time.Now().UTC()
	current, ok := s.state[key]
	if !ok || now.Sub(current.windowStartedAt) >= s.window {
		current = budgetCounterState{windowStartedAt: now, consumed: 0}
	}

	current.consumed++
	s.state[key] = current

	envelope := s.toEnvelope(controlType, strings.TrimSpace(subjectKey), current)
	if current.consumed > envelope.Limit {
		return envelope, &BudgetExhaustedError{Envelope: envelope}
	}

	return envelope, nil
}

func (s *InMemoryBudgetEnvelopeService) toEnvelope(controlType, subjectKey string, state budgetCounterState) BudgetEnvelope {
	limit := s.limits[controlType]
	remaining := limit - state.consumed
	if remaining < 0 {
		remaining = 0
	}

	return BudgetEnvelope{
		ControlType:        controlType,
		SubjectKey:         subjectKey,
		WindowStartedAtUTC: state.windowStartedAt.Format(time.RFC3339),
		WindowEndsAtUTC:    state.windowStartedAt.Add(s.window).Format(time.RFC3339),
		Limit:              limit,
		Consumed:           state.consumed,
		Remaining:          remaining,
		IsExhausted:        state.consumed >= limit,
	}
}

func buildBudgetKey(controlType, subjectKey string) string {
	trimmed := strings.TrimSpace(subjectKey)
	if trimmed == "" {
		panic("subjectKey is required")
	}

	return controlType + ":" + trimmed
}
