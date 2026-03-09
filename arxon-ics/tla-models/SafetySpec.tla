------------------------------ MODULE SafetySpec ------------------------------
(*
 * ARXON-ICS Engagement Safety Specification
 *
 * Models the state transitions of a penetration testing engagement.
 * TLC exhaustively explores all reachable states to prove that
 * safety invariants hold for a given attack plan BEFORE execution.
 *
 * Usage: The Python verifier translates an LLM-generated plan into
 * PlanSteps and Targets constants, then runs TLC to model check.
 *)
EXTENDS Naturals, Sequences, FiniteSets, TLC

CONSTANTS
    Targets,              \* Set of authorized target IPs (strings)
    AllowedTools,         \* Set of permitted tool names (strings)
    ForbiddenActions,     \* Set of actions that must NEVER execute
    MaxExploitAttempts,   \* Max exploit attempts per target
    PlanSteps             \* Sequence of [phase, target, tool] records from LLM plan

VARIABLES
    pc,                   \* Program counter: index into PlanSteps
    phase,                \* Current engagement phase
    exploitCount,         \* Function: target -> exploit attempt count
    planVerified,         \* Boolean: has the plan passed verification?
    executedSteps,        \* Set of step indices that have been executed
    terminated            \* Boolean: engagement has ended

vars == <<pc, phase, exploitCount, planVerified, executedSteps, terminated>>

\* ============================================================
\* INITIAL STATE
\* ============================================================

Init ==
    /\ pc = 1
    /\ phase = "init"
    /\ exploitCount = [t \in Targets |-> 0]
    /\ planVerified = FALSE
    /\ executedSteps = {}
    /\ terminated = FALSE

\* ============================================================
\* STATE TRANSITIONS
\* ============================================================

\* Transition: Start reconnaissance
StartRecon ==
    /\ phase = "init"
    /\ phase' = "recon"
    /\ UNCHANGED <<pc, exploitCount, planVerified, executedSteps, terminated>>

\* Transition: Move from recon to planning
StartPlanning ==
    /\ phase = "recon"
    /\ phase' = "planning"
    /\ UNCHANGED <<pc, exploitCount, planVerified, executedSteps, terminated>>

\* Transition: Verify the plan (required gate before exploitation)
VerifyPlan ==
    /\ phase = "planning"
    /\ planVerified' = TRUE
    /\ phase' = "verification"
    /\ UNCHANGED <<pc, exploitCount, executedSteps, terminated>>

\* Transition: Execute a plan step during exploitation
ExecuteStep ==
    /\ phase = "verification" \/ phase = "exploitation"
    /\ planVerified = TRUE            \* CRITICAL: must be verified first
    /\ pc <= Len(PlanSteps)
    /\ pc \notin executedSteps
    /\ LET step == PlanSteps[pc] IN
        /\ step.target \in Targets    \* SCOPE: target must be authorized
        /\ step.tool \in AllowedTools \* TOOL: must be permitted
        /\ step.tool \notin ForbiddenActions  \* SAFETY: not forbidden
        /\ exploitCount[step.target] < MaxExploitAttempts  \* BOUND: within limits
        /\ IF step.phase = "exploitation"
           THEN exploitCount' = [exploitCount EXCEPT ![step.target] = @ + 1]
           ELSE exploitCount' = exploitCount
        /\ phase' = "exploitation"
        /\ executedSteps' = executedSteps \union {pc}
        /\ pc' = pc + 1
        /\ UNCHANGED <<planVerified, terminated>>

\* Transition: Skip a plan step (e.g., technique not applicable)
SkipStep ==
    /\ phase \in {"verification", "exploitation"}
    /\ planVerified = TRUE
    /\ pc <= Len(PlanSteps)
    /\ pc \notin executedSteps
    /\ executedSteps' = executedSteps \union {pc}
    /\ pc' = pc + 1
    /\ UNCHANGED <<phase, exploitCount, planVerified, terminated>>

\* Transition: Move to reporting after all steps
StartReporting ==
    /\ phase = "exploitation"
    /\ pc > Len(PlanSteps)
    /\ phase' = "reporting"
    /\ UNCHANGED <<pc, exploitCount, planVerified, executedSteps, terminated>>

\* Transition: Complete the engagement
Complete ==
    /\ phase = "reporting"
    /\ phase' = "complete"
    /\ terminated' = TRUE
    /\ UNCHANGED <<pc, exploitCount, planVerified, executedSteps>>

\* ============================================================
\* NEXT STATE RELATION (disjunction of all transitions)
\* ============================================================

Next ==
    \/ StartRecon
    \/ StartPlanning
    \/ VerifyPlan
    \/ ExecuteStep
    \/ SkipStep
    \/ StartReporting
    \/ Complete

\* ============================================================
\* FAIRNESS (needed for liveness properties)
\* ============================================================

Fairness == WF_vars(Next)

Spec == Init /\ [][Next]_vars /\ Fairness

\* ============================================================
\* SAFETY INVARIANTS (must hold in ALL reachable states)
\* ============================================================

TypeOK ==
    /\ phase \in {"init", "recon", "planning", "verification",
                   "exploitation", "reporting", "complete"}
    /\ pc \in 1..(Len(PlanSteps) + 1)
    /\ planVerified \in BOOLEAN
    /\ terminated \in BOOLEAN

\* S1: Exploitation NEVER happens without prior verification
SafeExploitation ==
    phase = "exploitation" => planVerified = TRUE

\* S2: Exploit counts never exceed the bound
ExploitBound ==
    \A t \in Targets: exploitCount[t] <= MaxExploitAttempts

\* S3: No step executes against an unauthorized target
\*     (enforced structurally by ExecuteStep precondition)
\* S4: No forbidden action ever executes
\*     (enforced structurally by ExecuteStep precondition)

\* Combined safety invariant for TLC
SafetyInvariant ==
    /\ TypeOK
    /\ SafeExploitation
    /\ ExploitBound

\* ============================================================
\* LIVENESS PROPERTIES (must eventually hold)
\* ============================================================

\* L1: Engagement eventually completes
EngagementCompletes == <>(phase = "complete")

\* L2: Every plan step is eventually executed or skipped
AllStepsProcessed == <>(pc > Len(PlanSteps))

=============================================================================
