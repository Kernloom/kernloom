// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Adrian Enderlin

package main

import (
	"math"
	"math/rand"
	"sort"
	"time"
)

/* ---------------- Autotune reservoir ---------------- */

type reservoir struct {
	data   []float64
	cap    int
	seen   int
	rnd    *rand.Rand
	seeded bool
}

func newReservoir(capacity int) *reservoir {
	return &reservoir{cap: capacity, data: make([]float64, 0, capacity)}
}

func (r *reservoir) ensureSeed() {
	if r.seeded {
		return
	}
	r.seeded = true
	r.rnd = rand.New(rand.NewSource(time.Now().UnixNano()))
}

func (r *reservoir) Add(x float64) {
	if math.IsNaN(x) || math.IsInf(x, 0) || x < 0 {
		return
	}
	r.ensureSeed()
	r.seen++
	if len(r.data) < r.cap {
		r.data = append(r.data, x)
		return
	}
	j := r.rnd.Intn(r.seen)
	if j < r.cap {
		r.data[j] = x
	}
}

func median(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	cp := make([]float64, len(xs))
	copy(cp, xs)
	sort.Float64s(cp)
	m := len(cp) / 2
	if len(cp)%2 == 1 {
		return cp[m]
	}
	return (cp[m-1] + cp[m]) / 2
}

func mad(xs []float64, m float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	dev := make([]float64, len(xs))
	for i, x := range xs {
		dev[i] = math.Abs(x - m)
	}
	return median(dev)
}
