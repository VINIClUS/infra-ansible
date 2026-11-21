---------------------------- MODULE KeeperStages ----------------------------
EXTENDS Naturals, Sequences

CONSTANT TriggerRows

StageOrder == <<
    "application-prepare",
    "phase-b",
    "api",
    "static",
    "unit",
    "phase-c-recovery",
    "phase-c-audit",
    "final"
>>

ModelTriggerRows == <<
    <<"application-prepare", "prepared", "external", "phase-b">>,
    <<"phase-b", "phase-b", "external", "api">>,
    <<"api", "host", "external", "static">>,
    <<"static", "publish-static", "internal", "unit">>,
    <<"unit", "unit", "internal", "phase-c-recovery">>,
    <<"phase-c-recovery", "phase-c-recovery", "external", "phase-c-audit">>,
    <<"phase-c-audit", "phase-c-audit", "external", "final">>,
    <<"final", "terminal-readback", "internal", "terminal">>
>>

TerminalRows == <<
    <<"accepted-open", "final">>,
    <<"failed-closed-quiescent", "recovery">>,
    <<"failed-prepare-quiescent", "application-prepare">>
>>

CallerRows == <<
    <<"observer-bootstrap", "application-prepare", "none">>,
    <<"prepared", "application-prepare", "inventory">>,
    <<"phase-b", "phase-b", "none">>,
    <<"host", "api", "closed-ready">>,
    <<"phase-c-recovery", "phase-c-recovery", "none">>,
    <<"phase-c-audit", "phase-c-audit", "none">>
>>

OpRows == <<
    <<"application-prepare", "inventory", "observer-bootstrap">>,
    <<"application-prepare", "close-drain", "prepared">>,
    <<"api", "closed-ready", "none">>,
    <<"static", "publish-static", "host">>,
    <<"unit", "unit", "none">>,
    <<"phase-c-recovery", "recovery", "phase-c-recovery">>,
    <<"phase-c-audit", "audit", "phase-c-audit">>,
    <<"final", "reopen", "none">>,
    <<"final", "terminal-readback", "reopen">>,
    <<"recovery", "rollback-api-static", "none">>,
    <<"recovery", "terminal-readback", "rollback-api-static">>
>>

PrepareFailureOps == {"terminal-readback"}

BudgetRows == <<
    <<"application-prepare", 4>>,
    <<"phase-b", 2>>,
    <<"api", 3>>,
    <<"static", 3>>,
    <<"unit", 3>>,
    <<"phase-c-recovery", 3>>,
    <<"phase-c-audit", 3>>,
    <<"final", 4>>,
    <<"recovery", 6>>
>>

PrepareReserve == 4

RowSet(rows) == {rows[i] : i \in DOMAIN rows}
Stages == RowSet(StageOrder)
AllStages == Stages \cup {"recovery"}
Budget(s) == (CHOOSE r \in RowSet(BudgetRows) : r[1] = s)[2]
MaxBudget == 6
TerminalKinds == {r[1] : r \in RowSet(TerminalRows)}
FailedKinds == TerminalKinds \ {"accepted-open"}
TerminalStage(kind) == (CHOOSE r \in RowSet(TerminalRows) : r[1] = kind)[2]
CallerObservations == {r[1] : r \in RowSet(CallerRows)}
CallerRow(e) == CHOOSE r \in RowSet(CallerRows) : r[1] = e
CallerOwned(s) == {r[1] : r \in {x \in RowSet(CallerRows) : x[2] = s}}
Connected == {r[1] : r \in RowSet(TriggerRows)}
Trigger(s) == CHOOSE r \in RowSet(TriggerRows) : r[1] = s
InternalOp(s) == IF s \in Connected /\ Trigger(s)[3] = "internal" THEN {Trigger(s)[2]} ELSE {}
Ops(s) == {r[2] : r \in {x \in RowSet(OpRows) : x[1] = s}} \cup InternalOp(s)
Need(s, o) == {r[3] : r \in {x \in RowSet(OpRows) : x[1] = s /\ x[2] = o}} \ {"none"}
Keys == UNION {{<<s, o>> : o \in Ops(s)} : s \in AllStages}
        \cup {<<"application-prepare", o>> : o \in PrepareFailureOps}
OpNames == {k[2] : k \in Keys}
Deadline(s) == <<s, "deadline", "internal", "recovery">>

ASSUME \A i, j \in DOMAIN TriggerRows : TriggerRows[i][1] = TriggerRows[j][1] => i = j

VARIABLES stage, failing, budget, published, journal, trail, halted, terminal

vars == <<stage, failing, budget, published, journal, trail, halted, terminal>>

Live == terminal = "none" /\ ~halted
Normal == stage \in Stages /\ ~failing
Exhausted == failing \/ stage = "recovery"
Uncertain == {k \in Keys : journal[k] \in {"inflight", "unknown"}}
Inflight == \E k \in Keys : journal[k] = "inflight"
ActiveOps == IF failing THEN PrepareFailureOps ELSE Ops(stage)
FailureOps == IF stage = "recovery" THEN Ops("recovery") ELSE PrepareFailureOps
Satisfied(s, p) == IF p \in CallerObservations THEN p \in published ELSE journal[<<s, p>>] = "settled"
TriggerReady(s) ==
    IF Trigger(s)[3] = "external"
    THEN Trigger(s)[2] \in published
    ELSE journal[<<s, Trigger(s)[2]>>] = "settled"

Init ==
    /\ stage = "application-prepare"
    /\ failing = FALSE
    /\ budget = Budget("application-prepare")
    /\ published = {}
    /\ journal = [k \in Keys |-> "absent"]
    /\ trail = <<>>
    /\ halted = FALSE
    /\ terminal = "none"

Publish(e) ==
    /\ Live /\ Normal
    /\ e \notin published
    /\ CallerRow(e)[2] = stage
    /\ IF CallerRow(e)[3] = "none" THEN TRUE ELSE journal[<<stage, CallerRow(e)[3]>>] = "settled"
    /\ published' = published \cup {e}
    /\ UNCHANGED <<stage, failing, budget, journal, trail, halted, terminal>>

Start(o) ==
    /\ Live /\ Uncertain = {} /\ budget >= 1
    /\ o \in ActiveOps
    /\ journal[<<stage, o>>] = "absent"
    /\ \A p \in Need(stage, o) : Satisfied(stage, p)
    /\ journal' = [journal EXCEPT ![<<stage, o>>] = "inflight"]
    /\ UNCHANGED <<stage, failing, budget, published, trail, halted, terminal>>

Complete(k) ==
    /\ Live /\ journal[k] = "inflight"
    /\ \E result \in {"settled", "unknown"} : journal' = [journal EXCEPT ![k] = result]
    /\ budget' = budget - 1
    /\ UNCHANGED <<stage, failing, published, trail, halted, terminal>>

Reconcile(k) ==
    /\ Live /\ journal[k] = "unknown" /\ budget >= 1
    /\ journal' = [journal EXCEPT ![k] = "settled"]
    /\ budget' = budget - 1
    /\ UNCHANGED <<stage, failing, published, trail, halted, terminal>>

Wait ==
    /\ Live /\ Normal /\ ~Inflight /\ budget >= 1
    /\ budget' = budget - 1
    /\ UNCHANGED <<stage, failing, published, journal, trail, halted, terminal>>

OpsSettled(ops) == \A o \in ops : journal[<<stage, o>>] = "settled"

Leave ==
    /\ Live /\ Normal /\ budget >= 1 /\ Uncertain = {}
    /\ stage \in Connected
    /\ TriggerReady(stage)
    /\ trail' = Append(trail, Trigger(stage))
    /\ IF Trigger(stage)[4] = "terminal"
       THEN /\ stage = TerminalStage("accepted-open")
            /\ terminal' = "accepted-open"
            /\ UNCHANGED <<stage, budget>>
       ELSE /\ stage' = Trigger(stage)[4]
            /\ budget' = Budget(Trigger(stage)[4])
            /\ UNCHANGED terminal
    /\ UNCHANGED <<failing, published, journal, halted>>

Advance == Leave /\ OpsSettled(Ops(stage))

Exhaust ==
    /\ Live /\ Normal /\ budget = 0
    /\ IF stage = "application-prepare"
       THEN /\ failing' = TRUE
            /\ budget' = PrepareReserve
            /\ UNCHANGED <<stage, trail>>
       ELSE /\ stage' = "recovery"
            /\ budget' = Budget("recovery")
            /\ trail' = Append(trail, Deadline(stage))
            /\ UNCHANGED failing
    /\ UNCHANGED <<published, journal, halted, terminal>>

Refuse ==
    /\ Live /\ Normal /\ stage \notin Connected
    /\ halted' = TRUE
    /\ UNCHANGED <<stage, failing, budget, published, journal, trail, terminal>>

Close(kind) ==
    /\ Live /\ Uncertain = {} /\ budget >= 1
    /\ stage = TerminalStage(kind)
    /\ stage = "recovery" \/ failing
    /\ terminal' = kind
    /\ UNCHANGED <<stage, failing, budget, published, journal, trail, halted>>

Finish(kind) == Close(kind) /\ OpsSettled(FailureOps)

Done ==
    /\ terminal /= "none"
    /\ UNCHANGED vars

KeeperStep ==
    \/ \E o \in OpNames : Start(o)
    \/ \E k \in Keys : Complete(k) \/ Reconcile(k)
    \/ Advance
    \/ Exhaust
    \/ Refuse
    \/ \E kind \in FailedKinds : Finish(kind)

Next ==
    \/ \E e \in CallerObservations : Publish(e)
    \/ KeeperStep
    \/ Wait
    \/ Done

Fairness == WF_vars(KeeperStep) /\ WF_vars(Wait)

Spec == Init /\ [][Next]_vars /\ Fairness

Current == IF trail = <<>> THEN "application-prepare" ELSE trail[Len(trail)][4]
Position(s) == CHOOSE i \in DOMAIN StageOrder : StageOrder[i] = s
Successor(s) == IF Position(s) = Len(StageOrder) THEN "terminal" ELSE StageOrder[Position(s) + 1]

TypeOK ==
    /\ stage \in AllStages
    /\ failing \in BOOLEAN
    /\ halted \in BOOLEAN
    /\ budget \in 0..MaxBudget
    /\ published \subseteq CallerObservations
    /\ journal \in [Keys -> {"absent", "inflight", "unknown", "settled"}]
    /\ terminal \in {"none"} \cup TerminalKinds
    /\ trail \in Seq(RowSet(TriggerRows) \cup {Deadline(s) : s \in Stages})

NoSkipNoRevisit ==
    /\ \A i \in DOMAIN trail : trail[i][4] \in {"recovery", "terminal"} => i = Len(trail)
    /\ \A i \in DOMAIN trail :
        /\ trail[i][1] = IF i = 1 THEN "application-prepare" ELSE trail[i - 1][4]
        /\ trail[i][4] \in {Successor(trail[i][1]), "recovery"}
    /\ terminal = "none" => stage = Current

DeclaredTrigger ==
    \A i \in DOMAIN trail :
        IF trail[i][4] = "recovery"
        THEN trail[i] = Deadline(trail[i][1])
        ELSE /\ trail[i][1] \in Connected
             /\ trail[i] = Trigger(trail[i][1])
             /\ IF trail[i][3] = "external"
                THEN trail[i][2] \in CallerObservations /\ trail[i][2] \in published
                ELSE trail[i][2] \notin CallerObservations /\ journal[<<trail[i][1], trail[i][2]>>] = "settled"

CallerPublicationsBeforeLeaving ==
    \A i \in DOMAIN trail : trail[i][4] /= "recovery" => CallerOwned(trail[i][1]) \subseteq published

ExitWithOpsSettled ==
    /\ \A i \in DOMAIN trail :
        trail[i][4] /= "recovery" => \A o \in Ops(trail[i][1]) : journal[<<trail[i][1], o>>] = "settled"
    /\ terminal /= "none" => \A o \in ActiveOps : journal[<<stage, o>>] = "settled"

TerminalWithoutUncertainty == terminal /= "none" => Uncertain = {}

ExhaustionNeverAccepted == Exhausted => terminal \in {"none"} \cup FailedKinds

AcceptedAfterEveryStage ==
    terminal = "accepted-open" =>
        /\ ~Exhausted
        /\ Len(trail) = Len(StageOrder)
        /\ published = CallerObservations

Termination == <>(terminal /= "none")

ExhaustionEndsFailed == Exhausted ~> (terminal \in FailedKinds)

=============================================================================
