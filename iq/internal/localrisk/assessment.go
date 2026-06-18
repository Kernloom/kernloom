// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

// Package localrisk turns local signal aggregation into an explainable risk
// assessment that a Runtime PDP can consume.
package localrisk

import (
	"sort"
	"strings"
	"time"

	"github.com/kernloom/kernloom/pkg/core/signal"
	"github.com/kernloom/kernloom/pkg/riskaggregator"
)

type Level string

const (
	LevelLow      Level = "low"
	LevelMedium   Level = "medium"
	LevelHigh     Level = "high"
	LevelCritical Level = "critical"
)

type Assessment struct {
	SubjectID     string
	Level         Level
	Score         int
	Confidence    float64
	Completeness  float64
	Domains       []string
	Contributions []Contribution
	MissingInputs []string
	ValidUntil    time.Time
	Model         string
}

type Contribution struct {
	SignalID   string
	SignalType string
	Domain     string
	Score      int
	Confidence float64
	Weight     float64
}

type Config struct {
	Model        string
	DefaultTTL   time.Duration
	Completeness float64
}

func DefaultConfig() Config {
	return Config{
		Model:        "kliq.localrisk.v1",
		DefaultTTL:   2 * time.Minute,
		Completeness: 1.0,
	}
}

func FromAggregatorResult(result riskaggregator.Result, now time.Time, cfg Config) Assessment {
	if cfg.Model == "" {
		cfg.Model = DefaultConfig().Model
	}
	if cfg.DefaultTTL <= 0 {
		cfg.DefaultTTL = DefaultConfig().DefaultTTL
	}
	if cfg.Completeness <= 0 {
		cfg.Completeness = DefaultConfig().Completeness
	}

	contributions := make([]Contribution, 0, len(result.AllSignals))
	domainSet := map[string]bool{}
	confidenceSum := 0
	validUntil := now.UTC().Add(cfg.DefaultTTL)
	for i, sig := range result.AllSignals {
		domain := domainFor(sig.Type)
		domainSet[domain] = true
		confidenceSum += sig.Confidence
		contributions = append(contributions, Contribution{
			SignalID:   sig.ID,
			SignalType: string(sig.Type),
			Domain:     domain,
			Score:      sig.Score,
			Confidence: float64(sig.Confidence) / 100.0,
			Weight:     contributionWeight(i, len(result.AllSignals)),
		})
		if expiresAt := sig.ExpiresAt(); !expiresAt.IsZero() && expiresAt.Before(validUntil) {
			validUntil = expiresAt.UTC()
		}
	}

	domains := make([]string, 0, len(domainSet))
	for domain := range domainSet {
		domains = append(domains, domain)
	}
	sort.Strings(domains)

	confidence := 0.0
	if len(result.AllSignals) > 0 {
		confidence = float64(confidenceSum) / float64(len(result.AllSignals)) / 100.0
	}

	return Assessment{
		SubjectID:     result.SubjectID,
		Level:         levelForScore(result.ShadowRisk),
		Score:         clampScore(result.ShadowRisk),
		Confidence:    confidence,
		Completeness:  cfg.Completeness,
		Domains:       domains,
		Contributions: contributions,
		ValidUntil:    validUntil,
		Model:         cfg.Model,
	}
}

func FromSignals(signals []signal.Signal, now time.Time, cfg Config) []Assessment {
	results := riskaggregator.Aggregate(riskaggregator.Config{Mode: riskaggregator.ModeMaxScore}, signals)
	assessments := make([]Assessment, 0, len(results))
	for _, result := range results {
		assessments = append(assessments, FromAggregatorResult(result, now, cfg))
	}
	return assessments
}

func levelForScore(score int) Level {
	switch {
	case score >= 81:
		return LevelCritical
	case score >= 61:
		return LevelHigh
	case score >= 31:
		return LevelMedium
	default:
		return LevelLow
	}
}

func clampScore(score int) int {
	if score < 0 {
		return 0
	}
	if score > 100 {
		return 100
	}
	return score
}

func domainFor(sigType signal.SignalType) string {
	value := string(sigType)
	if idx := strings.IndexByte(value, '.'); idx > 0 {
		return value[:idx]
	}
	if value == "" {
		return "unknown"
	}
	return value
}

func contributionWeight(index, total int) float64 {
	if total <= 0 {
		return 0
	}
	if index == 0 {
		return 1.0
	}
	return 1.0 / float64(total)
}
