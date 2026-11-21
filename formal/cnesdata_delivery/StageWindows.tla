---------------------------- MODULE StageWindows ----------------------------
EXTENDS Naturals, Sequences

CONSTANTS AdmitMargin, ApplyTimeout, Over, ReviewPause, AllowEarly

Never == 10000
Fixed == 1800
FinalReserve == 420
ModeWindow == 900
StageDur == <<360, 180, 180, 120, 240, 240, 60>>
Stages == 1..7
DeployStages == {1, 5, 6}
Ops(s) == IF s \in DeployStages THEN <<"plan", "audit", "apply", "observe">>
          ELSE <<"effect", "observe">>
Bound(s, op) ==
    CASE op = "apply" -> ApplyTimeout
      [] op = "observe" -> 10
      [] s = 1 /\ op = "plan" -> 100
      [] s = 1 /\ op = "audit" -> 92
      [] s \in {5, 6} /\ op = "plan" -> 40
      [] s \in {5, 6} /\ op = "audit" -> 32
      [] s \in {2, 3} /\ op = "effect" -> 132
      [] s = 4 /\ op = "effect" -> 72
      [] s = 7 /\ op = "effect" -> 12
Rank(op) ==
    CASE op \in {"plan", "effect"} -> 1 [] op = "audit" -> 2 [] op = "apply" -> 3 [] OTHER -> 4
TotalOps == 20

Min(a, b) == IF a < b THEN a ELSE b

RECURSIVE SumFrom(_, _)
SumFrom(i, j) == IF i > j THEN 0 ELSE StageDur[i] + SumFrom(i + 1, j)
Later(s) == SumFrom(s + 1, 7)

VARIABLES stage, step, now, opened, term, missed, last, count

vars == <<stage, step, now, opened, term, missed, last, count>>

Deadline(s) == Min(Fixed, opened + StageDur[s])
NoEffect == [stage |-> 0, op |-> "none", start |-> 0, open |-> 0, secs |-> 0, dl |-> Never]
Durations(s, op) == {1, Bound(s, op)} \cup (IF Over > 0 THEN {Bound(s, op) + Over} ELSE {})

Init ==
    /\ stage = 1
    /\ step = 1
    /\ now = 0
    /\ opened = 0
    /\ term = "none"
    /\ missed = FALSE
    /\ last = NoEffect
    /\ count = 0

Admitted(s, op, start) ==
    /\ start + Bound(s, op) + AdmitMargin < Deadline(s)
    /\ Fixed - start >= (Deadline(s) - start) + Later(s) + FinalReserve

Advance(d, start, record) ==
    LET isLast == step = Len(Ops(stage)) IN
    /\ now' = start + d
    /\ last' = record
    /\ count' = count + 1
    /\ step' = IF isLast THEN 1 ELSE step + 1
    /\ stage' = IF isLast THEN stage + 1 ELSE stage
    /\ term' = IF isLast /\ stage = 7 THEN "accepted-open" ELSE "none"
    /\ opened' = IF isLast /\ stage < 7 THEN start + d ELSE opened
    /\ UNCHANGED missed

Run ==
    /\ term = "none"
    /\ LET op == Ops(stage)[step]
           start == now + IF stage \in DeployStages THEN ReviewPause ELSE 0 IN
       IF Admitted(stage, op, start)
         THEN \E d \in Durations(stage, op) :
                Advance(d, start, [stage |-> stage, op |-> op, start |-> start, open |-> opened,
                                   secs |-> Bound(stage, op), dl |-> Deadline(stage)])
         ELSE /\ term' = "failed-closed-quiescent"
              /\ missed' = TRUE
              /\ now' = start
              /\ UNCHANGED <<stage, step, opened, last, count>>

Early ==
    /\ AllowEarly /\ term = "none" /\ stage < 7
    /\ last' = [stage |-> stage + 1, op |-> Ops(stage + 1)[1], start |-> now, open |-> Never,
                secs |-> Bound(stage + 1, Ops(stage + 1)[1]), dl |-> Never]
    /\ UNCHANGED <<stage, step, now, opened, term, missed, count>>

Terminated == term # "none" /\ UNCHANGED vars

Next == Run \/ Early \/ Terminated

Spec == Init /\ [][Next]_vars /\ WF_vars(Run)

TypeOK ==
    /\ stage \in 1..8
    /\ step \in 1..4
    /\ now \in Nat
    /\ opened \in Nat
    /\ term \in {"none", "accepted-open", "failed-closed-quiescent"}
    /\ missed \in BOOLEAN
    /\ count \in 0..TotalOps

EffectsInsideStage ==
    /\ last.start >= last.open
    /\ last.start + last.secs + 37 < last.dl

JobOrder ==
    \/ stage = 8
    \/ last.stage = 0
    \/ last.stage < stage
    \/ last.stage = stage /\ Rank(last.op) < Rank(Ops(stage)[step])

WindowBound ==
    /\ stage = 8 \/ Deadline(stage) <= Fixed
    /\ stage = 8 \/ Deadline(stage) - opened <= Min(StageDur[stage], ModeWindow)

FailedNeverAccepted ==
    /\ term = "accepted-open" => ~missed /\ count = TotalOps
    /\ missed => term # "accepted-open"

InBoundsAccepts == term # "failed-closed-quiescent"

Terminates == <>(term # "none")
AcceptedWhenInBounds == <>(term = "accepted-open")
=============================================================================
