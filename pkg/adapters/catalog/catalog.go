// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

// Package catalog wires built-in adapter implementations behind generic KLIQ
// runtime interfaces. The KLIQ command imports this package instead of concrete
// adapter subpackages.
package catalog

import (
	"context"
	"fmt"
	"time"

	"github.com/kernloom/kernloom/pkg/adapterruntime"
	"github.com/kernloom/kernloom/pkg/adapters/klshield/client"
	shieldpep "github.com/kernloom/kernloom/pkg/adapters/klshield/pep"
	klshieldruntime "github.com/kernloom/kernloom/pkg/adapters/klshield/runtime"
	shieldtelemetry "github.com/kernloom/kernloom/pkg/adapters/klshield/telemetry"
	"github.com/kernloom/kernloom/pkg/componentinventory"
	"github.com/kernloom/kernloom/pkg/core/pdp"
)

type RuntimeFactory func(context.Context, adapterruntime.RuntimeAdapterSpec) (adapterruntime.ObservingAdapter, error)

const DefaultAdapterID = "klshield"

func CanonicalAdapterID(adapterID string) string {
	switch adapterID {
	case "", DefaultAdapterID, klshieldruntime.AdapterID:
		return DefaultAdapterID
	default:
		return adapterID
	}
}

func IsBindingAdapter(adapterID string) bool {
	switch adapterID {
	case "", DefaultAdapterID, klshieldruntime.AdapterID:
		return true
	default:
		return false
	}
}

type BindingConfig struct {
	AdapterID string
	NodeID    string
	BPFfsRoot string
	Interval  time.Duration
	PrevTTL   time.Duration
	DryRun    bool
}

type Binding struct {
	RuntimeAdapterID string
	TelemetryHandle  any
	SourcePEP        adapterruntime.SourcePEP
	RelationshipPEP  adapterruntime.RelationshipPEP
	FlowTelemetry    adapterruntime.Adapter
	RuntimeFactory   RuntimeFactory
	Inventory        componentinventory.ComponentRuntimeInventory
	Active           bool
	IPv6Active       bool
	Close            func() error
	TryOpenRelations func(root string)
}

func OpenBinding(ctx context.Context, cfg BindingConfig) (*Binding, error) {
	switch cfg.AdapterID {
	case "", DefaultAdapterID, klshieldruntime.AdapterID:
		return openKLShieldBinding(ctx, cfg)
	default:
		return nil, fmt.Errorf("unknown runtime adapter %q", cfg.AdapterID)
	}
}

func DefaultCapabilityParams(adapterID string) adapterruntime.CapabilityParams {
	switch adapterID {
	case "", DefaultAdapterID, klshieldruntime.AdapterID:
		return capabilityParams(shieldpep.DefaultCapabilityParams())
	default:
		return adapterruntime.CapabilityParams{}
	}
}

func CapabilityParamsFromPDP(adapterID string, cfg *pdp.Config) (adapterruntime.CapabilityParams, error) {
	switch adapterID {
	case "", DefaultAdapterID, klshieldruntime.AdapterID:
		p, err := shieldpep.CapabilityParamsFromPDP(cfg)
		return capabilityParams(p), err
	default:
		return adapterruntime.CapabilityParams{}, fmt.Errorf("unknown adapter %q", adapterID)
	}
}

func AdaptiveRateFactorsFromPDP(adapterID string, cfg *pdp.Config) (softFactor, hardFactor float64, err error) {
	switch adapterID {
	case "", DefaultAdapterID, klshieldruntime.AdapterID:
		return shieldpep.AdaptiveRateFactorsFromPDP(cfg)
	default:
		return 0, 0, fmt.Errorf("unknown adapter %q", adapterID)
	}
}

func capabilityParams(p shieldpep.CapabilityParams) adapterruntime.CapabilityParams {
	return adapterruntime.CapabilityParams{
		SoftRatePPS: p.SoftRatePPS,
		SoftBurst:   p.SoftBurst,
		HardRatePPS: p.HardRatePPS,
		HardBurst:   p.HardBurst,
		Cooldown:    p.Cooldown,
	}
}

func openKLShieldBinding(ctx context.Context, cfg BindingConfig) (*Binding, error) {
	maps, err := shieldclient.Open(cfg.BPFfsRoot, cfg.DryRun)
	if err != nil {
		return &Binding{
			RuntimeAdapterID: klshieldruntime.AdapterID,
			RuntimeFactory: func(ctx context.Context, spec adapterruntime.RuntimeAdapterSpec) (adapterruntime.ObservingAdapter, error) {
				return klshieldruntime.NewFromRuntimeSpec(ctx, spec)
			},
			Close: func() error { return nil },
		}, err
	}

	pep := shieldpep.New(maps, cfg.DryRun)
	if err := pep.Init(ctx, nil); err != nil {
		maps.Close()
		return nil, err
	}

	return &Binding{
		RuntimeAdapterID: klshieldruntime.AdapterID,
		TelemetryHandle:  maps,
		SourcePEP:        pep,
		RelationshipPEP:  pep,
		FlowTelemetry: shieldtelemetry.NewFromMaps(shieldtelemetry.Config{
			Interval: cfg.Interval,
			NodeID:   cfg.NodeID,
			PrevTTL:  cfg.PrevTTL,
		}, maps),
		RuntimeFactory: func(ctx context.Context, spec adapterruntime.RuntimeAdapterSpec) (adapterruntime.ObservingAdapter, error) {
			return klshieldruntime.NewFromRuntimeSpec(ctx, spec)
		},
		Inventory:  pep.BuildInventory(cfg.NodeID),
		Active:     true,
		IPv6Active: maps.Src6 != nil,
		Close: func() error {
			maps.Close()
			return nil
		},
		TryOpenRelations: func(root string) {
			maps.TryOpenEdgeMaps(root)
		},
	}, nil
}
