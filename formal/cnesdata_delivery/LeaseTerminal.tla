---------------------------- MODULE LeaseTerminal ----------------------------
EXTENDS Naturals

CONSTANTS Runs, Initial, NoRun, NoLease

TerminalKinds == {"accepted-open", "failed-closed-quiescent", "failed-prepare-quiescent"}
FailedKinds == {"failed-closed-quiescent", "failed-prepare-quiescent"}
PromotionResults == {"accepted", "failed"}
AdmittedResults == {"accepted"}
LeaseStatuses == {"held", "released"}
LeaseOutcomes == {"quiescent-released", "recovery_required", "reviewed_recovery"}

Phases == {"idle", "acquire", "prepare", "promote", "recovery", "terminal", "done", "exited"}
Executing == {"prepare", "promote", "recovery", "terminal"}
Owners == Runs \cup {Initial}
Records == [status: LeaseStatuses, owner: Owners, result: PromotionResults \cup {"none"}]

VARIABLES pc, kind, result, coord, lease, etag, seen, pred, reviewed, removed

vars == <<pc, kind, result, coord, lease, etag, seen, pred, reviewed, removed>>

Held(r) == lease /= NoLease /\ lease.status = "held" /\ lease.owner = r

Admissible(record) ==
    \/ record = NoLease
    \/ record.status = "released" /\ record.result \in AdmittedResults

Init ==
    /\ pc = [r \in Runs |-> "idle"]
    /\ kind = [r \in Runs |-> "none"]
    /\ result = [r \in Runs |-> "none"]
    /\ coord = [r \in Runs |-> "none"]
    /\ lease = [status |-> "released", owner |-> Initial, result |-> "accepted"]
    /\ etag = 0
    /\ seen = [r \in Runs |-> 0]
    /\ pred = [r \in Runs |-> NoRun]
    /\ reviewed = {}
    /\ removed = NoRun

Move(r, from, to) == pc[r] = from /\ pc' = [pc EXCEPT ![r] = to]

AcquireRead(r) ==
    /\ pc[r] = "idle"
    /\ IF Admissible(lease)
         THEN pc' = [pc EXCEPT ![r] = "acquire"] /\ seen' = [seen EXCEPT ![r] = etag]
         ELSE pc' = [pc EXCEPT ![r] = "exited"] /\ UNCHANGED seen
    /\ UNCHANGED <<kind, result, coord, lease, etag, pred, reviewed, removed>>

AcquireCas(r) ==
    /\ pc[r] = "acquire"
    /\ IF etag = seen[r]
         THEN /\ pc' = [pc EXCEPT ![r] = "prepare"]
              /\ pred' = [pred EXCEPT ![r] = IF lease = NoLease THEN removed ELSE lease.owner]
              /\ lease' = [status |-> "held", owner |-> r, result |-> "none"]
              /\ etag' = etag + 1
         ELSE /\ pc' = [pc EXCEPT ![r] = "exited"]
              /\ UNCHANGED <<pred, lease, etag>>
    /\ UNCHANGED <<kind, result, coord, seen, reviewed, removed>>

Close(r) ==
    /\ Move(r, "prepare", "promote")
    /\ UNCHANGED <<kind, result, coord, lease, etag, seen, pred, reviewed, removed>>

Decide(r) ==
    /\ Move(r, "promote", "recovery")
    /\ UNCHANGED <<kind, result, coord, lease, etag, seen, pred, reviewed, removed>>

Assess(r, from, terminal) ==
    /\ Move(r, from, "terminal")
    /\ kind' = [kind EXCEPT ![r] = terminal]
    /\ UNCHANGED <<result, coord, lease, etag, seen, pred, reviewed, removed>>

Accept(r) == Assess(r, "promote", "accepted-open")
Restore(r) == Assess(r, "recovery", "failed-closed-quiescent")
PrepareFail(r) == Assess(r, "prepare", "failed-prepare-quiescent")

Finish(r) ==
    /\ Move(r, "terminal", "done")
    /\ Held(r)
    /\ LET promotion == IF kind[r] \in FailedKinds THEN "failed" ELSE "accepted" IN
         /\ result' = [result EXCEPT ![r] = promotion]
         /\ lease' = [status |-> "released", owner |-> r, result |-> promotion]
    /\ coord' = [coord EXCEPT ![r] = "quiescent-released"]
    /\ etag' = etag + 1
    /\ UNCHANGED <<kind, seen, pred, reviewed, removed>>

Retain(r) ==
    /\ pc[r] \in Executing
    /\ pc' = [pc EXCEPT ![r] = "done"]
    /\ coord' = [coord EXCEPT ![r] = "recovery_required"]
    /\ UNCHANGED <<kind, result, lease, etag, seen, pred, reviewed, removed>>

ReviewedReset(r) ==
    /\ pc[r] = "done" /\ lease /= NoLease /\ lease.owner = r
    /\ \/ lease.status = "held" /\ coord[r] = "recovery_required"
       \/ lease.status = "released" /\ lease.result = "failed"
    /\ lease' = NoLease
    /\ removed' = r
    /\ reviewed' = reviewed \cup {r}
    /\ coord' = [coord EXCEPT ![r] = "reviewed_recovery"]
    /\ etag' = etag + 1
    /\ UNCHANGED <<pc, kind, result, seen, pred>>

Terminated ==
    /\ \A r \in Runs : pc[r] \in {"done", "exited"}
    /\ IF lease = NoLease THEN TRUE ELSE lease.status = "released"
    /\ UNCHANGED vars

RunStep(r) ==
    \/ AcquireRead(r) \/ AcquireCas(r) \/ Close(r) \/ Decide(r) \/ Accept(r)
    \/ Restore(r) \/ PrepareFail(r) \/ Finish(r) \/ Retain(r)

Next == (\E r \in Runs : RunStep(r) \/ ReviewedReset(r)) \/ Terminated

Fairness ==
    \A r \in Runs :
        /\ WF_vars(AcquireCas(r)) /\ WF_vars(Close(r)) /\ WF_vars(Accept(r))
        /\ WF_vars(Restore(r)) /\ WF_vars(Finish(r))

Spec == Init /\ [][Next]_vars /\ Fairness

TypeOK ==
    /\ pc \in [Runs -> Phases]
    /\ kind \in [Runs -> TerminalKinds \cup {"none"}]
    /\ result \in [Runs -> PromotionResults \cup {"none"}]
    /\ coord \in [Runs -> LeaseOutcomes \cup {"none"}]
    /\ lease \in Records \cup {NoLease}
    /\ etag \in Nat
    /\ seen \in [Runs -> Nat]
    /\ pred \in [Runs -> Owners \cup {NoRun}]
    /\ reviewed \subseteq Runs
    /\ removed \in Runs \cup {NoRun}

MutualExclusion == \A r1, r2 \in Runs : pc[r1] \in Executing /\ pc[r2] \in Executing => r1 = r2

ExecuteNeedsLease == \A r \in Runs : pc[r] \in Executing => Held(r)

FailedNeverAccepted ==
    \A r \in Runs : kind[r] \in FailedKinds =>
        /\ result[r] # "accepted"
        /\ lease /= NoLease /\ lease.owner = r => lease.result # "accepted"

RefuseFailedUntilReview ==
    \A r \in Runs : pred[r] \in Runs => result[pred[r]] \in AdmittedResults \/ pred[r] \in reviewed

HolderCanMove ==
    lease /= NoLease /\ lease.status = "held" => ENABLED (RunStep(lease.owner) \/ ReviewedReset(lease.owner))

AcquireEnds ==
    \A r \in Runs : pc[r] = "prepare" ~> coord[r] \in {"quiescent-released", "recovery_required"}

FailedStaysFailed ==
    [][\A r \in Runs :
        /\ kind[r] # "none" => kind'[r] = kind[r]
        /\ result[r] = "failed" => result'[r] = "failed"]_vars
=============================================================================
