------------------- MODULE KeeperStagesMutantNoApiTrigger -------------------
EXTENDS KeeperStages

NoApiTriggerRows == SelectSeq(ModelTriggerRows, LAMBDA r : r[1] /= "api")

=============================================================================
