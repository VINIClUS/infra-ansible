--------------- MODULE KeeperStagesMutantLapseOutsideRecovery ---------------
EXTENDS KeeperStages

OutsideHalt ==
    /\ terminal = "none" /\ stage /= "recovery"
    /\ halted' = TRUE
    /\ UNCHANGED <<stage, failing, budget, published, journal, trail, terminal, lapsed>>

MutantSpec == Init /\ [][Next \/ OutsideHalt]_vars /\ Fairness

=============================================================================
