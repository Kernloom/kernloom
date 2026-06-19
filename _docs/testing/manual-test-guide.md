# KLIQ Manual Test Guide

Dieses Dokument beschreibt den schnellen manuellen Testpfad nach dem Umbau von
KLIQ zum generischen Runtime-Orchestrator.

Ziel: erst beweisen, dass `kliq run` ohne privilegierte Adapter sauber startet,
dann `RuntimePolicyPack`/RuntimePDP, optional netfilter, KLShield, Forge und
Graph/Baseline-Pfade zuschalten.

**Voraussetzungen:**
- Go >= 1.23
- Linux
- Optional: Root-Rechte fuer netfilter/KLShield
- Optional: `sqlite3`, `jq`, `curl`, `timeout`

---

## 1. Build und Test-Baseline

```bash
cd /home/adrian/prj/ebpf-security/kernloom
mkdir -p bin

go build -o bin/kliq ./iq/cmd/kliq
go build -o bin/klshield ./shield/cmd/klshield

go test ./...
```

Erwartet: Build erfolgreich, alle Tests gruen.

Falls der Go-Cache in der Umgebung nicht beschreibbar ist:

```bash
GOCACHE=/tmp/kernloom-go-cache go test ./...
```

---

## 2. KLIQ ohne Adapter starten

Das ist der wichtigste Smoke-Test fuer den generischen Orchestrator. Er braucht
kein eBPF, kein netfilter und kein Root.

```bash
cd /home/adrian/prj/ebpf-security/kernloom
mkdir -p /tmp/kernloom-manual

cat > /tmp/kernloom-manual/whitelist.txt <<'EOF'
# Generische Subject-ID
ziti.identity:alice

# IP/CIDR bleibt als eine Match-Variante unter sourcefilters erlaubt
127.0.0.1
10.0.0.0/24
EOF

cat > /tmp/kernloom-manual/feedback.json <<'EOF'
[
  {"target":"ziti.identity:alice","action":"forgive","ttl":"1h"},
  {"target":"127.0.0.1","action":"whitelist","ttl":"15m"}
]
EOF

timeout 12s ./bin/kliq run \
  --adapter=none \
  --dry-run=true \
  --feature-profile=dos-light \
  --runtime-pdp-mode=shadow \
  --bootstrap=false \
  --autotune=false \
  --whitelist=/tmp/kernloom-manual/whitelist.txt \
  --feedback-file=/tmp/kernloom-manual/feedback.json \
  --state-file=/tmp/kernloom-manual/state.json \
  --db=/tmp/kernloom-manual/kliq-state.db \
  --interval=2s
```

Erwartet:
- `kliq run` startet und laeuft bis `timeout` beendet.
- Exit-Code `124` ist bei `timeout` normal.
- Log enthaelt sinngemaess: Catalog Adapter Binding wird uebersprungen,
  RuntimePDP ist im Shadow-Modus, KLIQ startet mit `adapter_active=false`.
- Whitelist/Feedback laden generische Subjects und IP/CIDR-Eintraege.

Wichtig: `run` ist Pflicht. `./bin/kliq --dry-run=true` ist absichtlich kein
gueltiger Startbefehl mehr.

`--runtime-pdp-mode=shadow` und `--dry-run=true` sind nicht dasselbe:
- `shadow` bedeutet: RuntimePDP evaluiert und loggt Entscheidungen, wird aber
  keine Enforcement-Aktion an einen PEP ausgeben.
- `dry-run=true` bedeutet: lokale Enforcement-Effekte werden nicht wirklich an
  PEPs wie KLShield oder netfilter geschrieben.

---

## 2.1 RuntimePolicyPack via --policy-file laden

Dieser Test prueft den neuen lokalen contracts-basierten Policy-Pfad. Er
braucht kein Root und keinen Adapter.

```bash
cd /home/adrian/prj/ebpf-security/kernloom
mkdir -p /tmp/kernloom-manual

cat > /tmp/kernloom-manual/runtime-policy.yaml <<'EOF'
apiVersion: kernloom.io/runtime/v1alpha1
kind: RuntimePolicyPack
metadata:
  name: manual-runtime-policy
  issued_at: "2026-06-19T10:00:00Z"
spec:
  default_effect: deny
  capabilities_required:
    - enforce.traffic.rate_limit
  rules:
    - id: hold-enforcement-while-drops
      when: "fsm.current_level in ['soft', 'hard', 'block'] && signals.enforcement.active"
      then:
        capability: enforce.traffic.rate_limit
        level: hard
        ttl: "30s"
        params:
          rate_pps: 100
      reason_codes:
        - rate_limit_drops_sustained
        - enforcement_hold
    - id: high-risk-rate-limit
      when: "risk.level in ['high', 'critical']"
      then:
        capability: enforce.traffic.rate_limit
        level: hard
        ttl: "30s"
        params:
          rate_pps: 100
      reason_codes:
        - manual_runtime_policy
EOF

timeout 12s ./bin/kliq run \
  --adapter=none \
  --policy-file=/tmp/kernloom-manual/runtime-policy.yaml \
  --runtime-pdp-mode=shadow \
  --dry-run=true \
  --feature-profile=dos-light \
  --bootstrap=false \
  --autotune=false \
  --whitelist=/tmp/kernloom-manual/whitelist.txt \
  --feedback-file=/tmp/kernloom-manual/feedback.json \
  --state-file=/tmp/kernloom-manual/state-runtime-policy.json \
  --db=/tmp/kernloom-manual/kliq-runtime-policy.db \
  --interval=2s
```

Erwartet:
- Log enthaelt `Policy loaded: ... kind=RuntimePolicyPack`.
- Log enthaelt `[runtime-pdp] pack loaded: 2 rules`.
- Log enthaelt `RuntimePDP mode: SHADOW`.
- Keine Meldungen wie `unsupported kind`, `parse runtime pack` oder
  `compile error`.

Hinweis: Ohne Adapter-Signale gibt es meist keine RuntimePDP-Entscheidungen.
Dieser Test prueft bewusst nur Laden, Validierung und Kompilierung des Packs.
`--runtime-pdp-mode=active` sollte erst genutzt werden, wenn das Policy Pack
fachlich passt und `--dry-run=false` wirklich gewollt ist.

`signals.enforcement.*` sind generische RuntimePDP-Facts fuer laufendes
PEP-Feedback:
- `signals.enforcement.feedback_rate`: generische Feedback-Rate.
- `signals.enforcement.drop_rate`: Drop-Rate; bei KLShield aktuell
  `network.rate_limit_drop_rate`.
- `signals.enforcement.deny_rate`: Deny-/Reject-Rate, aktuell `0` bis ein
  Adapter sie liefert.
- `signals.enforcement.throttle_rate`: Throttle-/Backpressure-Rate, aktuell `0`
  bis ein Adapter sie liefert.
- `signals.enforcement.active`: `true`, wenn eine dieser Raten groesser als
  `0` ist.

`signals.enforcement_feedback_rate` bleibt als alter Alias fuer
`signals.enforcement.feedback_rate` verwendbar.

---

## 3. State-Store pruefen

```bash
cd /home/adrian/prj/ebpf-security/kernloom

./bin/kliq storage status --db=/tmp/kernloom-manual/kliq-state.db
./bin/kliq relationships stats --db=/tmp/kernloom-manual/kliq-state.db
./bin/kliq relationships list --db=/tmp/kernloom-manual/kliq-state.db
./bin/kliq baselines list --db=/tmp/kernloom-manual/kliq-state.db
./bin/kliq status \
  --state-file=/tmp/kernloom-manual/state.json \
  --db=/tmp/kernloom-manual/kliq-state.db
```

Erwartet:
- `storage status` oeffnet die SQLite-DB und zeigt Tabellen wie `entities`,
  `relationships`, `metric_baselines`, `signals`, `decisions`.
- Ohne Adapter-Telemetrie sind Relationships/Baselines vermutlich leer. Das ist
  fuer diesen Smoke-Test korrekt.

---

## 4. Netfilter Dry-Run

Netfilter ist ein Enforcement-Adapter. Er liefert keine Primaer-Telemetrie.

```bash
cd /home/adrian/prj/ebpf-security/kernloom

timeout 15s sudo ./bin/kliq run \
  --adapter=netfilter \
  --dry-run=true \
  --feature-profile=dos-light \
  --runtime-pdp-mode=shadow \
  --bootstrap=false \
  --autotune=false \
  --whitelist=/tmp/kernloom-manual/whitelist.txt \
  --feedback-file=/tmp/kernloom-manual/feedback.json \
  --state-file=/tmp/kernloom-manual/state-netfilter.json \
  --db=/tmp/kernloom-manual/kliq-netfilter.db \
  --interval=2s
```

Erwartet:
- Wenn `nft` oder `iptables` vorhanden ist: Log `Netfilter adapter active`.
- Wenn kein Backend vorhanden ist: Warnung, aber kein Crash.
- Keine Graph-Telemetrie aus netfilter erwarten; conntrack ist nur optionaler
  Topology-Fallback.

---

## 5. KLShield Runtime-Smoke

Dieser Test nutzt den Default-Adapter `klshield`. Er ist nur sinnvoll, wenn die
KLShield/eBPF-Maps vorhanden sind oder die Umgebung bewusst als Dry-Run getestet
wird.

```bash
cd /home/adrian/prj/ebpf-security/kernloom

timeout 20s sudo ./bin/kliq run \
  --adapter=klshield \
  --dry-run=true \
  --feature-profile=dos-light \
  --runtime-pdp-mode=shadow \
  --whitelist=/tmp/kernloom-manual/whitelist.txt \
  --feedback-file=/tmp/kernloom-manual/feedback.json \
  --state-file=/tmp/kernloom-manual/state-klshield.json \
  --db=/tmp/kernloom-manual/kliq-klshield.db \
  --interval=2s
```

Erwartet:
- Mit verfuegbaren Maps startet der KLShield Runtime-Adapter.
- Ohne Maps ist eine Adapter-Warnung akzeptabel; der Prozess darf nicht paniken.
- KLShield-spezifische Metriken bleiben in `pkg/adapters/klshield/...`; KLIQ
  verarbeitet nur generische `SourceObservation`-Werte.

### 5.1 KLShield + Netfilter am selben KLIQ/PDP

Mehrere Adapter werden als kommagetrennte Liste angegeben. Der erste verfuegbare
Source-PEP fuehrt den lokalen FSM-State; weitere Source-PEPs spiegeln
autorisierte Transitionen als Sidecars. Relationship-PEPs werden gesammelt, so
dass Tuple-/Relationship-Enforcement von allen verfuegbaren passenden Adaptern
bedient werden kann.

```bash
cd /home/adrian/prj/ebpf-security/kernloom

timeout 20s sudo ./bin/kliq run \
  --adapter=klshield,netfilter \
  --dry-run=true \
  --feature-profile=dos-light \
  --runtime-pdp-mode=shadow \
  --whitelist=/tmp/kernloom-manual/whitelist.txt \
  --feedback-file=/tmp/kernloom-manual/feedback.json \
  --state-file=/tmp/kernloom-manual/state-multi-adapter.json \
  --db=/tmp/kernloom-manual/kliq-multi-adapter.db \
  --interval=2s
```

Erwartet:
- KLIQ loggt die angeforderten Adapter und die aktiven Inventory-/PEP-Bindings.
- Wenn Netfilter verfuegbar ist: `Netfilter adapter active`.
- RuntimePDP bleibt ein einzelner lokaler PDP; Adapter fuehren keine eigenen
  Policy-Entscheidungen aus.
- Wenn KLShield Maps fehlen, darf Netfilter trotzdem als Sidecar starten.

### 5.2 Remote-k6: schrittweise Eskalation und Deeskalation

Dieser Test nutzt zwei Geraete:
- Zielhost: Service, KLShield und KLIQ laufen hier.
- Lastgenerator: anderes Geraet im gleichen Netz, auf dem `k6` laeuft.

Ziel: beweisen, dass KLIQ die Remote-Source sieht, dann schrittweise
`OBSERVE -> RATE_SOFT -> RATE_HARD -> BLOCK` eskaliert und nach Ende der Last
wieder bis `OBSERVE` deeskaliert.

Wichtig:
- Nur in einem Labornetz ausfuehren.
- Wenn NAT, VPN, WSL, Load-Balancer oder ein Gateway dazwischen ist, sieht KLIQ
  eventuell nicht die echte k6-IP, sondern die Gateway-/NAT-IP.
- Fuer einen BLOCK-Test `--bootstrap=false` setzen. Aktiver Bootstrap kappt
  BLOCK bewusst auf `RATE_HARD`.
- Fuer diesen Test kein Policy Pack mit `max_action=rate_limit` verwenden,
  sonst ist BLOCK absichtlich nicht erlaubt.

Zielhost vorbereiten:

```bash
cd /home/adrian/prj/ebpf-security/kernloom
mkdir -p /tmp/kernloom-manual

# Interface waehlen, auf dem die Pakete vom k6-Geraet hereinkommen.
ip -br addr
export IFACE=eth0

# Testservice starten, falls kein eigener Service genutzt wird.
python3 -m http.server 8000 --bind 0.0.0.0
```

In einem zweiten Terminal auf dem Zielhost:

```bash
cd /home/adrian/prj/ebpf-security/kernloom

sudo ./bin/klshield attach-xdp \
  --iface "$IFACE" \
  --obj shield/bpf/out/xdp_kernloom_shield.bpf.o

# Optional: alte Testeintraege aus den KLShield-Maps entfernen.
sudo ./bin/klshield reset || true

cat > /tmp/kernloom-manual/whitelist-empty.txt <<'EOF'
# leer lassen: die k6-Source darf fuer diesen Test NICHT whitelisted sein
EOF

printf '[]\n' > /tmp/kernloom-manual/feedback-empty.json

cat > /tmp/kernloom-manual/k6-runtime-policy.yaml <<'EOF'
apiVersion: kernloom.io/runtime/v1alpha1
kind: RuntimePolicyPack
metadata:
  name: manual-k6-runtime-policy
spec:
  default_effect: deny
  capabilities_required:
    - enforce.traffic.rate_limit
    - enforce.access.deny
  rules:
    - id: fsm-intent-block
      when: "fsm.proposed_level == 'block'"
      then:
        capability: enforce.access.deny
        level: block
        ttl: "30s"
      reason_codes:
        - manual_k6_fsm_block
    - id: hold-enforcement-while-drops
      when: "fsm.current_level in ['soft', 'hard', 'block'] && signals.enforcement.active"
      then:
        capability: enforce.traffic.rate_limit
        level: hard
        ttl: "30s"
      reason_codes:
        - rate_limit_drops_sustained
        - enforcement_hold
    - id: fsm-intent-hard
      when: "fsm.proposed_level == 'hard'"
      then:
        capability: enforce.traffic.rate_limit
        level: hard
        ttl: "30s"
      reason_codes:
        - manual_k6_fsm_hard
    - id: fsm-intent-soft
      when: "fsm.proposed_level == 'soft'"
      then:
        capability: enforce.traffic.rate_limit
        level: soft
        ttl: "30s"
      reason_codes:
        - manual_k6_fsm_soft
    - id: fsm-intent-observe
      when: "fsm.proposed_level == 'observe' && fsm.current_level != 'observe'"
      then:
        level: observe
        ttl: "30s"
      reason_codes:
        - manual_k6_fsm_observe
EOF
```

KLIQ zuerst im Dry-Run starten:

```bash
cd /home/adrian/prj/ebpf-security/kernloom

sudo ./bin/kliq run \
  --adapter=klshield \
  --policy-file=/tmp/kernloom-manual/k6-runtime-policy.yaml \
  --feature-profile=dos-light \
  --runtime-pdp-mode=active \
  --dry-run=true \
  --bootstrap=false \
  --autotune=false \
  --min-pps=1 \
  --trig-pps=20 \
  --trig-syn=20 \
  --trig-scan=5 \
  --trig-bps=0 \
  --sev-delta1=1 \
  --sev-delta2=1 \
  --sev-delta3=1 \
  --soft-at=2 \
  --hard-at=7 \
  --block-at=12 \
  --up-need=1 \
  --down-need=2 \
  --soft-ttl=10s \
  --hard-ttl=10s \
  --block-ttl=10s \
  --min-hold-soft=0s \
  --min-hold-hard=0s \
  --block-min-sev=0 \
  --block-min-dur=0s \
  --soft-rate-factor=0.5 \
  --hard-rate-factor=0.1 \
  --whitelist=/tmp/kernloom-manual/whitelist-empty.txt \
  --feedback-file=/tmp/kernloom-manual/feedback-empty.json \
  --state-file=/tmp/kernloom-manual/state-k6-dryrun.json \
  --db=/tmp/kernloom-manual/kliq-k6-dryrun.db \
  --interval=1s \
  2>&1 | tee /tmp/kernloom-manual/kliq-k6-dryrun.log
```

Auf dem k6-Geraet:

```bash
cat > stresstest-k6.js <<'EOF'
import http from 'k6/http';

export const options = {
  stages: [
    { duration: '10s', target: 50 },
    { duration: '25s', target: 200 },
    { duration: '20s', target: 200 },
    { duration: '15s', target: 0 },
  ],
};

export default function () {
  http.get(__ENV.TARGET, { timeout: '2s' });
}
EOF

TARGET=http://ZIELHOST_IP:8000 k6 run stresstest-k6.js
```

Dry-Run Erwartung auf dem Zielhost:

```bash
grep -E 'STATE|ACTION-RECEIPT|TICK#|top:' /tmp/kernloom-manual/kliq-k6-dryrun.log
```

Erwartet:
- Die Source in `top:` oder `STATE` ist die IP des k6-Geraets. Wenn dort die
  Gateway-IP steht, liegt NAT dazwischen.
- Log zeigt nacheinander mindestens:
  - `STATE <k6-ip> OBSERVE->RATE_SOFT`
  - `STATE <k6-ip> RATE_SOFT->RATE_HARD`
  - optional `STATE <k6-ip> RATE_HARD->BLOCK`
- Im Dry-Run gibt es keine echten Drops; `runtime-pdp-mode=active` plus
  `dry_run=true` prueft Detection, RuntimePolicyPack, Broker-/Receipt-Pfad und
  Logging ohne PEP-Effekt.

Echte Enforcement-Variante:

1. KLIQ mit `Ctrl-C` stoppen.
2. KLShield-Maps resetten.
3. KLIQ mit denselben Flags, aber `--dry-run=false` starten.
4. k6 erneut ausfuehren.

```bash
sudo ./bin/klshield reset || true

sudo ./bin/kliq run \
  --adapter=klshield \
  --policy-file=/tmp/kernloom-manual/k6-runtime-policy.yaml \
  --feature-profile=dos-light \
  --runtime-pdp-mode=active \
  --dry-run=false \
  --bootstrap=false \
  --autotune=false \
  --min-pps=1 \
  --trig-pps=20 \
  --trig-syn=20 \
  --trig-scan=5 \
  --trig-bps=0 \
  --sev-delta1=1 \
  --sev-delta2=1 \
  --sev-delta3=1 \
  --soft-at=2 \
  --hard-at=7 \
  --block-at=12 \
  --up-need=1 \
  --down-need=2 \
  --soft-ttl=10s \
  --hard-ttl=10s \
  --block-ttl=10s \
  --min-hold-soft=0s \
  --min-hold-hard=0s \
  --block-min-sev=0 \
  --block-min-dur=0s \
  --soft-rate-factor=0.5 \
  --hard-rate-factor=0.1 \
  --whitelist=/tmp/kernloom-manual/whitelist-empty.txt \
  --feedback-file=/tmp/kernloom-manual/feedback-empty.json \
  --state-file=/tmp/kernloom-manual/state-k6-enforce.json \
  --db=/tmp/kernloom-manual/kliq-k6-enforce.db \
  --interval=1s \
  2>&1 | tee /tmp/kernloom-manual/kliq-k6-enforce.log
```

Waehrend k6 laeuft:

```bash
grep -E 'STATE|ACTION-RECEIPT|TICK#|top:' /tmp/kernloom-manual/kliq-k6-enforce.log
sudo ./bin/klshield stats
```

Erwartet:
- `STATE <k6-ip> OBSERVE->RATE_SOFT`
- `STATE <k6-ip> RATE_SOFT->RATE_HARD`
- `STATE <k6-ip> RATE_HARD->BLOCK` oder mindestens `RATE_HARD`, wenn der
  Test zu kurz oder die Last zu niedrig ist.
- `ACTION-RECEIPT` fuer Apply-Aktionen.
- `klshield stats` zeigt steigende `drop_rl` oder `drop_deny`.

Deeskalation testen:

1. k6 auslaufen lassen oder mit `Ctrl-C` stoppen.
2. KLIQ weiterlaufen lassen.
3. 45-60 Sekunden warten. Mit `soft/hard/block-ttl=10s`, `down-need=2` und
   KLShield-Cooldown von 5s laeuft die Rueckwaertskette nicht sofort, sondern
   schrittweise.

```bash
grep -E 'STATE .*->(RATE_HARD|RATE_SOFT|OBSERVE)|TICK#' \
  /tmp/kernloom-manual/kliq-k6-enforce.log
```

Erwartet:
- Nach Lastende erscheinen Rueckwaerts-Transitionen, z.B.:
  - `STATE <k6-ip> BLOCK->RATE_HARD`
  - `STATE <k6-ip> RATE_HARD->RATE_SOFT`
  - `STATE <k6-ip> RATE_SOFT->OBSERVE`
- Spaetere Ticks zeigen `fsm{soft=0 hard=0 block=0}`.
- Vom k6-Geraet funktioniert ein normaler Request wieder:

```bash
curl -fsS http://ZIELHOST_IP:8000 >/dev/null && echo recovered
```

Wenn keine Eskalation sichtbar ist:
- Pruefen, ob `klshield stats` ueberhaupt `pkts`/`pass` zaehlt.
- Pruefen, ob KLIQ die k6-IP oder nur eine NAT-/Gateway-IP sieht.
- `--trig-pps` weiter senken, z.B. auf `5`.
- Sicherstellen, dass die k6-IP nicht in Whitelist oder Feedback steht.
- Sicherstellen, dass `--bootstrap=false` gesetzt ist, wenn BLOCK erwartet wird.
- Bei sehr schnellem BLOCK statt sichtbarer Zwischenstufen `--hard-at` und
  `--block-at` erhoehen oder die k6-Last reduzieren.

---

## 6. Graph und Baselines

Graph Learning braucht eine Telemetriequelle. Mit `--adapter=none` bleiben die
Stores leer, aber die CLI-Pfade muessen trotzdem funktionieren.

```bash
cd /home/adrian/prj/ebpf-security/kernloom

timeout 20s sudo ./bin/kliq run \
  --adapter=klshield \
  --dry-run=true \
  --feature-profile=graph-learning \
  --graph=true \
  --runtime-pdp-mode=shadow \
  --state-file=/tmp/kernloom-manual/state-graph.json \
  --db=/tmp/kernloom-manual/kliq-graph.db \
  --interval=2s

./bin/kliq relationships stats --db=/tmp/kernloom-manual/kliq-graph.db
./bin/kliq relationships list --db=/tmp/kernloom-manual/kliq-graph.db
./bin/kliq baselines list \
  --db=/tmp/kernloom-manual/kliq-graph.db \
  --scope=relationship
```

Erwartet:
- `storage status --db=/tmp/kernloom-manual/kliq-graph.db` zeigt Rows in
  `entities`, `relationships` und `metric_baselines`.
- `baselines list` zeigt pro Metrik den gelernten `BASELINE`-Wert. Das ist der
  EWMA-Normalwert fuer diese Metrik und diesen Scope. `PEAK` ist der gelernte
  Spitzenwert, `CONF` die Baseline-Confidence von 0 bis 1, `OBS` die Anzahl
  Beobachtungen.
- `--scope=relationship` filtert Baselines, die an eine gelernte Beziehung
  gebunden sind, z.B. eine Netzwerk-Kante wie "source IP connects_to target
  tuple". Andere Scopes koennen z.B. entity-/subject-basierte Baselines sein.

Neue generische Graph-Signale, die in Logs/Stores auftauchen koennen:
- `graph.new_relationship_dim`
- `graph.edge_metric_deviation`
- `graph.edge_metric_peak_exceeds`

Alte Signalnamen wie `graph.edge_baseline_pps_deviation` sollten nicht mehr in
neuem Code oder neuen Daten auftauchen.

---

## 7. Forge Managed-Smoke

In einem zweiten Terminal:

```bash
cd /home/adrian/prj/ebpf-security/kernloom-forge
mkdir -p bin
go build -o bin/forge ./cmd/forge
./bin/forge serve --addr :18443
```

Health-Check:

```bash
curl -s http://localhost:18443/healthz
```

Erwartet: `ok`.

KLIQ mit Forge verbinden:

```bash
cd /home/adrian/prj/ebpf-security/kernloom

timeout 20s ./bin/kliq run \
  --adapter=none \
  --mode=managed \
  --dry-run=true \
  --forge-url=http://localhost:18443 \
  --forge-enroll-token=dev-token \
  --runtime-pdp-mode=shadow \
  --bootstrap=false \
  --autotune=false \
  --whitelist=/tmp/kernloom-manual/whitelist.txt \
  --feedback-file=/tmp/kernloom-manual/feedback.json \
  --state-file=/tmp/kernloom-manual/state-managed.json \
  --db=/tmp/kernloom-manual/kliq-managed.db \
  --interval=2s
```

Erwartet:
- Enrollment/Heartbeat-Log oder eine klare Forge-Warnung.
- Kein Adapter-spezifischer Crash.
- Ohne zugewiesenes Bundle sind RuntimePDP-Entscheidungen weiterhin leer oder
  Shadow-only.

Receipts pruefen:

```bash
sqlite3 /tmp/kernloom-manual/kliq-managed.db \
  "SELECT id, status, upload_status FROM action_receipts LIMIT 10;"
```

Falls keine Aktionen passiert sind, ist eine leere Result-Menge normal.

---

## 8. Forge als Policy-Builder fuer Standalone-KLIQ

Dieser Pfad nutzt Forge nicht als laufenden Control-Plane-Server, sondern als
Policy-Compiler fuer einen lokalen Operator-Workflow:

1. Enterprise-Intent als `AccessPolicy` schreiben.
2. Forge gegen Adapter-Manifeste und Target-Profile kompilieren lassen.
3. Den Forge-Plan pruefen: deployable, compensating controls, downgrades,
   unsupported requirements.
4. Daraus ein lokales KLIQ-`RuntimePolicyPack` bauen und mit
   `kliq run --policy-file=...` laden.

Wichtig: `forge compile --output yaml` erzeugt aktuell einen
`kind: EnforcementPlan`. Das ist ein Governance-/Compiler-Report und noch
nicht direkt das Datei-Format fuer `kliq --policy-file`. Standalone-KLIQ laedt
lokal:

```yaml
apiVersion: kernloom.io/runtime/v1alpha1
kind: RuntimePolicyPack
```

Forge ist in diesem Ablauf also der sichere Compiler/Validator, der zeigt,
welche Anforderungen fuer ein Target nativ, partiell, delegiert oder als
Runtime-Kompensation umgesetzt werden sollen. Die finale Standalone-Datei ist
danach ein KLIQ-`RuntimePolicyPack`.

Forge bauen:

```bash
cd /home/adrian/prj/ebpf-security/kernloom-forge
export PATH=$PATH:/usr/local/go/bin
mkdir -p bin
go build -o bin/forge ./cmd/forge
```

Ein minimales Standalone-Intent fuer einen Edge-/Router-Node anlegen:

```bash
mkdir -p /tmp/kernloom-manual/forge-profiles
cp examples/profiles/klshield-local.yaml /tmp/kernloom-manual/forge-profiles/

cat > /tmp/kernloom-manual/standalone-edge-access.yaml <<'EOF'
apiVersion: kernloom.io/v1
kind: AccessPolicy
metadata:
  name: standalone-edge-access
  owner: lab-operator
spec:
  subject:
    type: role
    ref: edge-clients
  action: access
  resource:
    type: service
    ref: public-edge
  conditions:
    - id: require-low-risk
      type: risk_level
      signal: subject.risk.level
      operator: eq
      value: low
  effect: allow
EOF
```

Intent und KLShield-Adaptermanifest validieren:

```bash
./bin/forge validate \
  --policy /tmp/kernloom-manual/standalone-edge-access.yaml

./bin/forge validate-adapter \
  --adapter examples/adapters/klshield/capability.yaml
```

Policy gegen das lokale KLShield-Target kompilieren:

```bash
./bin/forge compile \
  --policy /tmp/kernloom-manual/standalone-edge-access.yaml \
  --adapters examples/adapters \
  --profiles /tmp/kernloom-manual/forge-profiles \
  --output summary

./bin/forge compile \
  --policy /tmp/kernloom-manual/standalone-edge-access.yaml \
  --adapters examples/adapters \
  --profiles /tmp/kernloom-manual/forge-profiles \
  --output yaml \
  > /tmp/kernloom-manual/forge-standalone-plan.yaml
```

Erwartet:
- Die Summary enthaelt `standalone-edge-access -> klshield-local`.
- `deployable` bedeutet: alle Requirements sind mindestens implementiert,
  partiell, delegiert oder als kompensierender Runtime-Control abgedeckt.
- `compensating=require-low-risk` bedeutet: Forge erwartet fuer diese
  Anforderung eine RuntimePDP-Regel in KLIQ.
- `unsupported=...` bedeutet: nicht blind weitermachen. Erst entscheiden, ob
  das Intent, das Target-Profil oder die Adapter-Faehigkeiten angepasst werden
  muessen.
- `partial`/`downgraded` bedeutet: die Semantik wurde vereinfacht, z.B. Rolle
  oder Service wird bei KLShield auf lokale Netzwerk-/Cgroup-Sicht reduziert.

Den Plan inspizieren:

```bash
grep -E 'target:|deployable:|status:|capability:|action:|unsupported|downgrade' \
  /tmp/kernloom-manual/forge-standalone-plan.yaml
```

Fuer Standalone-KLIQ daraus ein lokales RuntimePolicyPack erstellen:

```bash
cat > /tmp/kernloom-manual/standalone-runtime-policy.yaml <<'EOF'
apiVersion: kernloom.io/runtime/v1alpha1
kind: RuntimePolicyPack
metadata:
  name: standalone-klshield-runtime-policy
  issued_at: "2026-06-19T10:00:00Z"
spec:
  default_effect: deny
  capabilities_required:
    - enforce.traffic.rate_limit
    - enforce.access.deny
  rules:
    - id: hold-active-enforcement
      when: "fsm.current_level in ['soft', 'hard', 'block'] && signals.enforcement.active"
      then:
        capability: enforce.traffic.rate_limit
        level: hard
        ttl: "30s"
        params:
          rate_pps: 100
      reason_codes:
        - forge_standalone_hold
        - enforcement_feedback_active

    - id: critical-risk-deny
      when: "risk.level == 'critical'"
      then:
        capability: enforce.access.deny
        level: block
        ttl: "30s"
      reason_codes:
        - forge_compensating_control
        - risk_critical

    - id: high-risk-rate-limit
      when: "risk.level == 'high'"
      then:
        capability: enforce.traffic.rate_limit
        level: hard
        ttl: "30s"
        params:
          rate_pps: 100
      reason_codes:
        - forge_compensating_control
        - risk_high
EOF
```

Warum diese drei Regeln:
- `hold-active-enforcement` verhindert Oszillation. Wenn der PEP weiterhin
  Drops/Deny/Throttle-Feedback meldet, erneuert KLIQ die Lease, auch wenn die
  Post-Enforcement-Telemetrie sauberer aussieht.
- `critical-risk-deny` ist die harte Kompensation fuer kritisches Risiko.
- `high-risk-rate-limit` ist die konservative Kompensation fuer hohes Risiko.

Regel-Reihenfolge ist relevant: RuntimePDP nimmt die erste passende Regel.
Darum steht Hold vor neuen Eskalationen und `critical` vor `high`.

Hinweis zu Capability-Namen:
- Forge-Adapterkataloge koennen adapterseitige Action-IDs wie
  `network.flow_rate_limit` oder `network.flow_deny` zeigen.
- Das Standalone-`RuntimePolicyPack` fuer KLIQ sollte die contracts-basierten
  Runtime-Capabilities verwenden: `enforce.traffic.rate_limit` und
  `enforce.access.deny`.

Policy lokal ohne PEP-Effekt pruefen:

```bash
cd /home/adrian/prj/ebpf-security/kernloom

timeout 12s ./bin/kliq run \
  --adapter=none \
  --policy-file=/tmp/kernloom-manual/standalone-runtime-policy.yaml \
  --runtime-pdp-mode=shadow \
  --dry-run=true \
  --feature-profile=dos-light \
  --bootstrap=false \
  --autotune=false \
  --state-file=/tmp/kernloom-manual/state-forge-standalone-shadow.json \
  --db=/tmp/kernloom-manual/kliq-forge-standalone-shadow.db \
  --interval=2s
```

Erwartet:
- `Policy loaded: ... kind=RuntimePolicyPack`
- `[runtime-pdp] pack loaded: 3 rules`
- `RuntimePDP mode: SHADOW`

Danach mit KLShield als Standalone-KLIQ im Dry-Run starten:

```bash
sudo ./bin/kliq run \
  --adapter=klshield \
  --policy-file=/tmp/kernloom-manual/standalone-runtime-policy.yaml \
  --runtime-pdp-mode=active \
  --dry-run=true \
  --feature-profile=dos-light \
  --bootstrap=false \
  --autotune=false \
  --state-file=/tmp/kernloom-manual/state-forge-standalone-klshield.json \
  --db=/tmp/kernloom-manual/kliq-forge-standalone-klshield.db \
  --interval=1s
```

Erwartet:
- RuntimePDP ist `active`, aber wegen `--dry-run=true` wird noch nichts real in
  KLShield geschrieben.
- Bei passenden Signalen erscheinen `[runtime-pdp:active] DECISION ...` und
  `ACTION-RECEIPT`-Logs.
- Erst nach erfolgreichem Dry-Run und bewusstem Operator-Entscheid
  `--dry-run=false` verwenden.

Merksatz: Forge beantwortet hier "ist mein Intent fuer dieses Target fachlich
abdeckbar?". KLIQ beantwortet lokal "welche Runtime-Aktion soll ich jetzt fuer
dieses konkrete Subject ausfuehren?".

---

## 9. Integrationstest-Skripte

Die manuellen Schritte oben koennen durch die Integrationstest-Skripte
abgesichert werden.

No-XDP/ohne Root fuer den RuntimePolicyPack-Pfad:

```bash
cd /home/adrian/prj/ebpf-security/kernloom
KLT_SCENARIOS=12 bash tests/integration/run-forge.sh
```

Erwartet:
- `bin/kliq` wird bei Bedarf gebaut.
- Szenario `12_runtime_policy_pack.sh` startet `kliq run --adapter=none` mit
  `kind: RuntimePolicyPack`.
- Danach laufen gezielte Contract-Tests fuer Loader, Signaturpruefung,
  `RuntimeDecision -> ActionProposal`, Broker-Revert und RuntimeBundle
  Conformance.

No-XDP Control-Plane-Gruppe:

```bash
make integration-forge
```

Das fuehrt standardmaessig Szenarien 09, 10 und 12 aus. Forge wird nur fuer
09/10 gebaut; Szenario 12 braucht keinen Forge-Server.

Voller XDP/netns-Lauf:

```bash
make integration
```

Hinweis: Der volle Lauf braucht sudo, XDP/netns-faehige Linux-Umgebung und
optional netfilter-Tools fuer Szenario 11. Artefakte landen unter
`/tmp/kernloom-integration-artifacts-<uid>/<run-id>/`, nicht im Repository.

---

## 10. OpenZiti Decoder/Mapping Tests

Diese Tests brauchen keinen Controller:

```bash
cd /home/adrian/prj/ebpf-security/kernloom

go test -v ./pkg/adapters/openziti/decoder/...
go test -v ./pkg/adapters/openziti/mapping/...
go test -v ./pkg/adapters/openziti/relationshiplearner/...
```

Optional mit realem Controller:

```bash
cat > /tmp/openziti-test.go <<'EOF'
package main

import (
	"context"
	"fmt"

	"github.com/kernloom/kernloom/pkg/adapters/openziti/eventsource"
)

func main() {
	cv, err := eventsource.DiscoverVersion(context.Background(),
		eventsource.Config{BaseURL: "https://YOUR-CONTROLLER:1280", APIToken: "YOUR-TOKEN"},
		nil)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Version: %s\nCompatible: %v\nWarnings: %v\n",
		cv.Version, cv.Compatible, cv.Warnings)
}
EOF

go run /tmp/openziti-test.go
```

---

## 11. Was nach dem Umbau bewusst anders ist

- KLIQ startet ueber `kliq run [flags]`; Subcommands sind explizit.
- Der State-Store heisst `--db`; `--state-store-path` ist alt.
- `--policy-file` akzeptiert `kind: LocalPolicyPack` und
  `kind: RuntimePolicyPack` mit `apiVersion: kernloom.io/runtime/v1alpha1`.
- Whitelist und Feedback matchen generische Subject-IDs. IP/CIDR ist nur eine
  unterstuetzte Subject-Form fuer netzwerkbasierte Adapter.
- Adapter-spezifische Telemetrie, Tuning-Details und Enforcement-Schluessel
  gehoeren in `pkg/adapters/<adapter>/...`, nicht in `iq/cmd/kliq`.
- Graph/Baseline-Daten sind metrisch und subject-/relationship-basiert. Neue
  Adapter sollen eigene Metric-IDs und Dimensionen liefern, statt KLIQ auf IP,
  Port oder PPS zu koppeln.
- RuntimePDP-Entscheidungen werden in `active` in `ActionProposal`s gemappt und
  durch den Action Broker mit Lease/Receipt/Revert-Pfad gefuehrt. Der alte
  direkte Beziehungspfad ist nicht mehr der Zielpfad.

---

## 12. Haeufige Probleme

| Problem | Loesung |
|---|---|
| `unknown command` oder KLIQ startet nicht | `run` fehlt: `./bin/kliq run ...` verwenden |
| `flag provided but not defined: -state-store-path` | Neues Flag nutzen: `--db=/tmp/kernloom-manual/kliq-state.db` |
| `timeout` liefert Exit-Code `124` | Erwartet, wenn der Smoke-Test den laufenden Agent beendet |
| `go: command not found` | `export PATH=$PATH:/usr/local/go/bin` |
| `kliq: no such file` | `go build -o bin/kliq ./iq/cmd/kliq` |
| `unsupported kind` bei `--policy-file` | Top-level `kind` pruefen: aktuell `LocalPolicyPack` oder `RuntimePolicyPack` |
| `compile runtime policy file` | CEL-Ausdruck, Capability, Level oder TTL im RuntimePolicyPack pruefen |
| `Netfilter adapter ... no backend found` | `nft`/`iptables` fehlt oder Root-Rechte fehlen; fuer Orchestrator-Smoke `--adapter=none` nutzen |
| KLShield Maps fehlen | Erst KLShield/eBPF Setup starten oder den unprivilegierten Smoke-Test nutzen |
| Relationships/Baselines leer | Ohne Telemetriequelle normal; Graph Learning braucht Adapter-Observations |
| Forge-Server nicht erreichbar | Port pruefen: `lsof -i :18443` |
| `forge compile --output yaml` laedt nicht via `--policy-file` | Das ist ein `EnforcementPlan`. Fuer Standalone-KLIQ ein `RuntimePolicyPack` mit `apiVersion: kernloom.io/runtime/v1alpha1` erstellen |
