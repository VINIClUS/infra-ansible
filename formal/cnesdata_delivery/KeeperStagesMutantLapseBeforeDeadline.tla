--------------- MODULE KeeperStagesMutantLapseBeforeDeadline ----------------
EXTENDS KeeperStages

EarlyHalt ==
    /\ terminal = "none" /\ stage = "recovery" /\ ~lapsed /\ "host-recovery" \notin published
    /\ halted' = TRUE
    /\ UNCHANGED <<stage, failing, budget, published, journal, trail, terminal, lapsed>>

MutantSpec == Init /\ [][Next \/ EarlyHalt]_vars /\ Fairness

=============================================================================
