------------------------- MODULE LeaseTerminalMutantO22 -------------------------
EXTENDS LeaseTerminal

AcquireOverFailure(r) ==
    /\ pc[r] = "idle"
    /\ lease.status = "released" /\ lease.result = "failed" /\ ~lease.recovered
    /\ pc' = [pc EXCEPT ![r] = "acquire"]
    /\ seen' = [seen EXCEPT ![r] = etag]
    /\ UNCHANGED <<kind, result, coord, lease, etag, pred, reviewed>>

MutantSpec == Init /\ [][Next \/ \E r \in Runs : AcquireOverFailure(r)]_vars /\ Fairness
=============================================================================
