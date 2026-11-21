------------------ MODULE KeeperStagesMutantLeaveUnsettled ------------------
EXTENDS KeeperStages

MutantSpec == Init /\ [][Next \/ Leave]_vars /\ Fairness

=============================================================================
