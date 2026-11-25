------------------- MODULE LeaseTerminalMutantResetUnreviewed -------------------
EXTENDS LeaseTerminal

ResetUnreviewed(r) ==
    /\ pc[r] = "done" /\ lease /= NoLease /\ lease.owner = r
    /\ \/ lease.status = "held" /\ coord[r] = "recovery_required"
       \/ lease.status = "released" /\ lease.result = "failed"
    /\ lease' = NoLease
    /\ removed' = r
    /\ coord' = [coord EXCEPT ![r] = "reviewed_recovery"]
    /\ etag' = etag + 1
    /\ UNCHANGED <<pc, kind, result, seen, pred, reviewed>>

MutantSpec == Init /\ [][Next \/ \E r \in Runs : ResetUnreviewed(r)]_vars /\ Fairness
=============================================================================
