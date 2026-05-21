// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package metricbaseline

import (
	"math"
	"time"
)

// Profile holds the learned state for one metric+scope+subject combination.
// It uses exponential weighted moving average (EWMA) for the expected value
// and EWMA variance for measuring the spread of normal values.
//
// Promotion: a profile is promoted (trusted) once it has accumulated enough
// observations, active windows, and age. Unpromoted profiles can be scored
// but with low confidence.
type Profile struct {
	Key Key

	// EWMA is the exponentially weighted moving average of observed values.
	// Represents the expected (normal) value for this metric.
	EWMA float64

	// EWMAVariance is the exponentially weighted variance.
	// Updated as: EWMAVariance = α * (value - EWMA)² + (1-α) * EWMAVariance
	// sqrt(EWMAVariance) is the effective "sigma" for deviation scoring.
	EWMAVariance float64

	// Peak is the highest non-suspicious value seen after promotion.
	Peak float64

	// Count is the total number of updates (including suspicious ones).
	Count uint64

	// LearnedCount is the number of updates that actually modified the EWMA
	// (i.e. non-suspicious updates after promotion).
	LearnedCount uint64

	// SuspiciousCount is the number of updates skipped due to suspicious=true.
	SuspiciousCount uint64

	// FirstSeen is when this profile was first created.
	FirstSeen time.Time

	// LastSeen is when this profile was last updated.
	LastSeen time.Time

	// Promoted is true once the profile has enough data to be trusted.
	Promoted bool

	// Confidence is a score 0.0–1.0 reflecting how much the baseline can be trusted.
	// Computed from observation count, active windows (proxy via LearnedCount), and age.
	Confidence float64
}

// update applies a new value to the profile. If suspicious is true, the
// EWMA/variance are not updated (anti-poisoning) but count is still incremented.
// alpha is the learning rate for non-promoted profiles; alphaPromoted for promoted ones.
func (p *Profile) update(value float64, suspicious bool, now time.Time, alpha, alphaPromoted float64, minCount uint64) {
	p.Count++
	p.LastSeen = now

	if suspicious {
		p.SuspiciousCount++
		// Score-only: do not learn from suspicious windows.
		return
	}

	a := alpha
	if p.Promoted {
		a = alphaPromoted
	}

	// First update: initialise EWMA directly.
	if p.LearnedCount == 0 {
		p.EWMA = value
		p.EWMAVariance = 0
		p.LearnedCount = 1
		if p.FirstSeen.IsZero() {
			p.FirstSeen = now
		}
		p.checkPromotion(minCount, now)
		return
	}

	// EWMA update: new value pulls mean toward itself.
	delta := value - p.EWMA
	p.EWMA += a * delta

	// EWMA variance update (using the post-mean-update delta for accuracy).
	// This is the Welford-EWMA variant: variance tracks spread around the mean.
	p.EWMAVariance = (1-a)*p.EWMAVariance + a*delta*delta

	p.LearnedCount++

	// Track peak after promotion.
	if p.Promoted && value > p.Peak {
		p.Peak = value
	}

	p.checkPromotion(minCount, now)
	p.recomputeConfidence()
}

func (p *Profile) checkPromotion(minCount uint64, now time.Time) {
	if p.Promoted {
		return
	}
	if p.LearnedCount >= minCount {
		p.Promoted = true
		p.Peak = p.EWMA // initialise peak at baseline on promotion
	}
}

// recomputeConfidence updates the Confidence field.
// Confidence grows with learned observations and age relative to typical targets.
func (p *Profile) recomputeConfidence() {
	const targetCount = 100.0  // observations for full count confidence
	const targetAgeSec = 86400 // 24h for full age confidence

	countScore := math.Min(float64(p.LearnedCount)/targetCount, 1.0)
	age := time.Since(p.FirstSeen).Seconds()
	ageScore := math.Min(age/targetAgeSec, 1.0)
	p.Confidence = 0.6*countScore + 0.4*ageScore
}

// sigma returns the standard deviation estimate from EWMA variance.
// A small floor prevents division-by-zero when the variance is near zero.
func (p *Profile) sigma(floor float64) float64 {
	s := math.Sqrt(p.EWMAVariance)
	if s < floor {
		return floor
	}
	return s
}
