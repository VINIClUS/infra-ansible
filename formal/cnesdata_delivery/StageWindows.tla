---------------------------- MODULE StageWindows ----------------------------
EXTENDS Naturals, Sequences

CONSTANTS FixedWindow, AdmitMargin, InitTimeout, ShowTimeout, PlanTimeout, ApplyTimeout,
          ReadbackFloor, InitActual, ShowActual, ApplyActual, JobActual, PubActual, Over,
          ReviewPause, AllowEarly, CheckCompletion, ModeCeiling, InfeasibleStages, FirstStage,
          AdapterFloor, ReadbackPostGuards, PublishGuardsPerFile, TrailingGuards, PlanFiles,
          AuditFiles, DeployFiles, StageDur, StageVar

Never == 10000
FinalReserve == 420
Stages == 1..7
PauseStages == {5, 6}
CodeDur == <<360, 180, 180, 120, 240, 240, 60>>
E2Dur == <<360, 180, 180, 180, 330, 330, 90>>
CodeVar == <<
    [plan |-> 37, aread |-> 37, pread |-> 37],
    [api_effect |-> 71, api_observe |-> 71],
    [static_publish |-> 135, static_settle |-> 7],
    [unit_seed |-> 28, unit_start |-> 27, unit_observe |-> 27],
    [plan |-> 1, aread |-> 1, pread |-> 1, recovery_seed |-> 1, recovery_start |-> 1, recovery_observe |-> 1],
    [plan |-> 1, aread |-> 1, pread |-> 1, audit_start |-> 1, audit_observe |-> 1],
    [reopen |-> 11, terminal_readback |-> 11]
>>

E2Var == <<
    [plan |-> 37, aread |-> 37, pread |-> 37],
    [api_effect |-> 71, api_observe |-> 71],
    [static_publish |-> 135, static_settle |-> 7],
    [unit_seed |-> 48, unit_start |-> 47, unit_observe |-> 47],
    [plan |-> 17, aread |-> 17, pread |-> 17, recovery_seed |-> 16, recovery_start |-> 16, recovery_observe |-> 16],
    [plan |-> 20, aread |-> 20, pread |-> 20, audit_start |-> 20, audit_observe |-> 19],
    [reopen |-> 26, terminal_readback |-> 26]
>>

UnitModeOps == <<"unit_seed", "unit_start", "unit_observe">>
RecoveryModeOps == <<"recovery_seed", "recovery_start", "recovery_observe">>
AuditModeOps == <<"audit_start", "audit_observe">>
RECURSIVE Rep(_, _)
Rep(seq, n) == IF n = 0 THEN <<>> ELSE seq \o Rep(seq, n - 1)
Trail == Rep(<<"tail">>, TrailingGuards)
Publish(files) == Rep(<<"pub">>, PublishGuardsPerFile * files)
Read(op, guard) == <<op>> \o Rep(<<guard>>, ReadbackPostGuards)
Job1 == <<"job1", "init1", "plan", "show1">> \o Trail \o Publish(PlanFiles)
Job2 == <<"job2", "init2", "show2">> \o Trail \o Publish(AuditFiles)
Job3 == <<"job3", "init3">> \o Read("aread", "aread_g") \o <<"show3", "apply">> \o Read("pread", "pread_g")
        \o Trail \o Publish(DeployFiles)
DeployOps == Job1 \o Job2 \o Job3

Ops(s) ==
    CASE s = 1 -> DeployOps
      [] s = 2 -> <<"api_effect", "api_observe">>
      [] s = 3 -> <<"static_publish", "static_settle">>
      [] s = 4 -> UnitModeOps
      [] s = 5 -> DeployOps \o RecoveryModeOps
      [] s = 6 -> DeployOps \o AuditModeOps
      [] s = 7 -> <<"reopen", "terminal_readback">>

RECURSIVE SumLen(_)
SumLen(s) == IF s > 7 THEN 0 ELSE Len(Ops(s)) + SumLen(s + 1)
TotalOps == SumLen(1)
RECURSIVE OpsBefore(_)
OpsBefore(s) == IF s <= 1 THEN 0 ELSE Len(Ops(s - 1)) + OpsBefore(s - 1)

Min(a, b) == IF a < b THEN a ELSE b
Max(a, b) == IF a > b THEN a ELSE b

RECURSIVE SumFrom(_, _)
SumFrom(i, j) == IF i > j THEN 0 ELSE StageDur[i] + SumFrom(i + 1, j)
Later(s) == SumFrom(s + 1, 7)

IsJob(op) == op \in {"job1", "job2", "job3"}
IsInit(op) == op \in {"init1", "init2", "init3"}
IsShow(op) == op \in {"show1", "show2", "show3"}
IsGuard(op) == op \in {"tail", "aread_g", "pread_g"}
IsFixed(op) == IsJob(op) \/ IsInit(op) \/ IsShow(op) \/ IsGuard(op) \/ op \in {"apply", "pub"}
Bound(s, op) ==
    CASE IsJob(op) -> JobActual
      [] IsInit(op) -> InitActual
      [] IsShow(op) -> ShowActual
      [] op = "apply" -> ApplyActual
      [] op = "pub" -> PubActual
      [] IsGuard(op) -> 0
      [] OTHER -> StageVar[s][op]
Declared(s, op) ==
    CASE IsJob(op) -> ReadbackFloor
      [] IsInit(op) -> InitTimeout
      [] IsShow(op) -> ShowTimeout
      [] op = "plan" -> PlanTimeout
      [] op = "apply" -> ApplyTimeout
      [] op \in {"aread", "pread"} -> Max(ReadbackFloor, Bound(s, op))
      [] op \in {"pub", "tail", "aread_g", "pread_g"} -> ReadbackFloor
      [] OTHER -> Max(AdapterFloor, Bound(s, op))

VARIABLES stage, step, now, opened, ctxOpen, term, missed, lateOp, last, count

vars == <<stage, step, now, opened, ctxOpen, term, missed, lateOp, last, count>>

Deadline(s) == Min(FixedWindow, opened + StageDur[s])
NoEffect == [stage |-> 0, idx |-> 0, op |-> "none", start |-> 0, open |-> 0, secs |-> 0,
             dl |-> Never, end |-> 0]
Durations(s, op) ==
    IF IsFixed(op) THEN {Bound(s, op)}
    ELSE {1, Bound(s, op)} \cup (IF Over > 0 THEN {Bound(s, op) + Over} ELSE {})

Init ==
    /\ stage = FirstStage
    /\ step = 1
    /\ now = 0
    /\ opened = 0
    /\ ctxOpen = Never
    /\ term = "none"
    /\ missed = FALSE
    /\ lateOp = FALSE
    /\ last = NoEffect
    /\ count = OpsBefore(FirstStage)

Admitted(s, op, start) ==
    /\ start + Declared(s, op) + AdmitMargin < Deadline(s)
    /\ FixedWindow - start >= (Deadline(s) - start) + Later(s) + FinalReserve

Finish(start, d, record) ==
    LET isLast == step = Len(Ops(stage))
        late == start + d >= Deadline(stage) IN
    /\ now' = start + d
    /\ last' = record
    /\ count' = count + 1
    /\ step' = IF isLast THEN 1 ELSE step + 1
    /\ stage' = IF isLast THEN stage + 1 ELSE stage
    /\ lateOp' = (lateOp \/ late)
    /\ term' = IF isLast /\ stage = 7 THEN
                 (IF CheckCompletion /\ (lateOp \/ late) THEN "failed-closed-quiescent"
                  ELSE "accepted-open")
               ELSE "none"
    /\ missed' = (isLast /\ stage = 7 /\ CheckCompletion /\ (lateOp \/ late))
    /\ opened' = IF isLast /\ stage < 7 THEN start + d ELSE opened
    /\ ctxOpen' = IF isLast /\ stage = 3 THEN start + d ELSE ctxOpen

Refuse(start) ==
    /\ term' = "failed-closed-quiescent"
    /\ missed' = TRUE
    /\ now' = start
    /\ UNCHANGED <<stage, step, opened, ctxOpen, lateOp, last, count>>

Run ==
    /\ term = "none"
    /\ LET op == Ops(stage)[step]
           start == now + IF IsJob(op) /\ stage \in PauseStages THEN ReviewPause ELSE 0
           record(d) == [stage |-> stage, idx |-> step, op |-> op, start |-> start,
                         open |-> opened, secs |-> Declared(stage, op), dl |-> Deadline(stage),
                         end |-> start + d] IN
       IF Admitted(stage, op, start)
         THEN \E d \in Durations(stage, op) :
                IF CheckCompletion /\ d > Declared(stage, op)
                  THEN Refuse(start + Declared(stage, op))
                  ELSE Finish(start, d, record(d))
         ELSE Refuse(start)

Early ==
    /\ AllowEarly /\ term = "none" /\ stage < 7
    /\ last' = [stage |-> stage + 1, idx |-> 1, op |-> "early", start |-> now, open |-> Never,
                secs |-> 1, dl |-> Never, end |-> now]
    /\ UNCHANGED <<stage, step, now, opened, ctxOpen, term, missed, lateOp, count>>

Terminated == term # "none" /\ UNCHANGED vars

Next == Run \/ Early \/ Terminated

Spec == Init /\ [][Next]_vars /\ WF_vars(Run)

TypeOK ==
    /\ stage \in 1..8
    /\ step \in 1..40
    /\ now \in Nat
    /\ opened \in Nat
    /\ ctxOpen \in Nat
    /\ term \in {"none", "accepted-open", "failed-closed-quiescent"}
    /\ missed \in BOOLEAN
    /\ lateOp \in BOOLEAN
    /\ count \in 0..TotalOps

EffectsInsideStage ==
    /\ last.start >= last.open
    /\ last.start + last.secs + 37 < last.dl

JobOrder ==
    \/ term # "none"
    \/ last.stage = 0
    \/ last.stage < stage
    \/ last.stage = stage /\ last.idx < step

AcceptBeforeDeadline ==
    term = "accepted-open" => ~lateOp /\ last.end < last.dl

ModeSpan == ctxOpen = Never \/ now - ctxOpen <= ModeCeiling

FailedNeverAccepted ==
    /\ term = "accepted-open" => ~missed /\ count = TotalOps /\ InfeasibleStages = {}
    /\ missed => term # "accepted-open"

InBoundsAccepts ==
    term = "failed-closed-quiescent" => stage \in InfeasibleStages

Terminates == <>(term # "none")
Resolved == <>(term = IF InfeasibleStages = {} THEN "accepted-open" ELSE "failed-closed-quiescent")
=============================================================================
