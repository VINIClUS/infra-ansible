---------------------- MODULE LeaseTerminalMutantResetLive ----------------------
EXTENDS LeaseTerminal

ResetLive(r) ==
    /\ lease /= NoLease /\ lease.owner = r
    /\ lease' = NoLease
    /\ removed' = r
    /\ reviewed' = reviewed \cup {r}
    /\ coord' = [coord EXCEPT ![r] = "reviewed_recovery"]
    /\ etag' = etag + 1
    /\ UNCHANGED <<pc, kind, result, seen, pred>>

MutantSpec == Init /\ [][Next \/ \E r \in Runs : ResetLive(r)]_vars /\ Fairness
=============================================================================
