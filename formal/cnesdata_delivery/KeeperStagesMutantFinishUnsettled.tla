----------------- MODULE KeeperStagesMutantFinishUnsettled ------------------
EXTENDS KeeperStages

MutantSpec == Init /\ [][Next \/ \E kind \in FailedKinds : Close(kind)]_vars /\ Fairness

=============================================================================
