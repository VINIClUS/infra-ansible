-------------------- MODULE LeaseTerminalMutantReachability --------------------
EXTENDS LeaseTerminal

NoFullStory ==
    ~ /\ \E r \in Runs : kind[r] = "accepted-open" /\ result[r] = "accepted"
      /\ \E r \in Runs : kind[r] = "failed-closed-quiescent" /\ result[r] = "failed" /\ r \in reviewed
      /\ \E r \in Runs : coord[r] = "reviewed_recovery" /\ result[r] = "none"
      /\ \E r \in Runs : kind[r] = "failed-prepare-quiescent" /\ result[r] = "failed"
      /\ \E r \in Runs : pred[r] \in reviewed
=============================================================================
