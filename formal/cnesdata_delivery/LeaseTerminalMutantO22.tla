------------------------- MODULE LeaseTerminalMutantO22 -------------------------
EXTENDS LeaseTerminal

AcquireOverFailure(r) ==
    /\ pc[r] = "idle"
    /\ lease /= NoLease /\ lease.status = "released" /\ lease.result = "failed"
    /\ pc' = [pc EXCEPT ![r] = "acquire"]
    /\ seen' = [seen EXCEPT ![r] = etag]
    /\ UNCHANGED <<kind, result, coord, lease, etag, pred, reviewed, removed>>

MutantSpec == Init /\ [][Next \/ \E r \in Runs : AcquireOverFailure(r)]_vars /\ Fairness
=============================================================================
