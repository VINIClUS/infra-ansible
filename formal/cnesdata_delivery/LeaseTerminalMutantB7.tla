------------------------- MODULE LeaseTerminalMutantB7 -------------------------
EXTENDS LeaseTerminal

Abandon(r) ==
    /\ pc[r] \in Executing
    /\ pc' = [pc EXCEPT ![r] = "done"]
    /\ UNCHANGED <<kind, result, coord, lease, etag, seen, pred, reviewed, removed>>

MutantSpec == Init /\ [][Next \/ \E r \in Runs : Abandon(r)]_vars /\ Fairness
=============================================================================
