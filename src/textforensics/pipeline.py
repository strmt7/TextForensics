"""Detection Pipeline Orchestrator for TextForensics.

Provides DAG-based workflow orchestration for AI-text detection pipelines with:
- DAG-based workflow execution with dependency resolution
- Cost-aware routing with budget enforcement
- A/B testing framework with statistical significance
- Canary deployments with gradual rollout
- Feature flags with gradual rollout
- Multi-model ensemble with weighted voting
- Cost tracking and budget enforcement

Design principles:
- Local-first: No network dependencies
- Observable: Full tracing and metrics
- Extensible: Plugin architecture for custom steps
- Observable: Full tracing and metrics
- Cost-aware: Budget enforcement with soft/hard limits
"""

from __future__ import annotations

import asyncio
import hashlib
import random
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    pass

__all__ = [
    "PipelineStep",
    "PipelineStatus",
    "PipelineDAG",
    "PipelineExecution",
    "StepResult",
    "CostTracker",
    "BudgetPolicy",
    "ABTest",
    "CanaryDeployment",
    "FeatureFlag",
    "EnsembleVoter",
    "PipelineOrchestrator",
    "create_pipeline_orchestrator",
]


class PipelineStatus(str, Enum):
    """Status of a pipeline execution."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMEOUT = "timeout"


class StepStatus(str, Enum):
    """Status of a pipeline step."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    RETRYING = "retrying"


@dataclass(frozen=True, slots=True)
class PipelineStep:
    """A single step in a pipeline DAG."""
    id: str
    name: str
    dependencies: list[str] = field(default_factory=list)
    timeout_seconds: float = 300.0
    retry_count: int = 0
    retry_delay: float = 1.0
    cost_estimate_usd: float = 0.0
    required: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "dependencies": self.dependencies,
            "timeout_seconds": self.timeout_seconds,
            "retry_count": self.retry_count,
            "retry_delay": self.retry_delay,
            "cost_estimate_usd": self.cost_estimate_usd,
            "required": self.required,
            "metadata": self.metadata,
        }


@dataclass
class StepResult:
    """Result of executing a pipeline step."""
    step_id: str
    status: StepStatus
    output: Any = None
    error: str | None = None
    duration_ms: float = 0.0
    cost_usd: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "step_id": self.step_id,
            "status": self.status.value,
            "output": self.output,
            "error": self.error,
            "duration_ms": self.duration_ms,
            "cost_usd": self.cost_usd,
            "metadata": self.metadata,
        }


class PipelineDAG:
    """Directed Acyclic Graph for pipeline execution."""

    def __init__(self, steps: list[PipelineStep]):
        self.steps = {step.id: step for step in steps}
        self._validate_dag()

    def _validate_dag(self) -> None:
        """Validate the DAG has no cycles and all dependencies exist."""
        # Check all dependencies exist
        step_ids = set(self.steps.keys())
        for step in self.steps.values():
            for dep in step.dependencies:
                if dep not in step_ids:
                    raise ValueError(f"Step {step.id} depends on non-existent step {dep}")

        # Check for cycles using Kahn's algorithm
        # in_degree tracks how many dependencies each step has
        in_degree = {step_id: 0 for step_id in self.steps}
        for step in self.steps.values():
            for _dep in step.dependencies:
                # step depends on _dep, so step has one more incoming edge
                in_degree[step.id] += 1

        queue = [step_id for step_id, deg in in_degree.items() if deg == 0]
        processed = 0

        while queue:
            node = queue.pop(0)
            processed += 1
            for other_step in self.steps.values():
                if node in other_step.dependencies:
                    in_degree[other_step.id] -= 1
                    if in_degree[other_step.id] == 0:
                        queue.append(other_step.id)

        if processed != len(self.steps):
            raise ValueError("Pipeline DAG contains cycles")

    def topological_order(self) -> list[str]:
        """Return steps in topological execution order."""
        in_degree = {step_id: 0 for step_id in self.steps}
        for step in self.steps.values():
            for _dep in step.dependencies:
                in_degree[step.id] += 1

        queue = [step_id for step_id, deg in in_degree.items() if deg == 0]
        result = []

        while queue:
            node = queue.pop(0)
            result.append(node)
            for other_step in self.steps.values():
                if node in other_step.dependencies:
                    in_degree[other_step.id] -= 1
                    if in_degree[other_step.id] == 0:
                        queue.append(other_step.id)

        return result

    def get_parallel_groups(self) -> list[list[str]]:
        """Return steps grouped by parallel execution level."""
        in_degree = {step_id: 0 for step_id in self.steps}
        for step in self.steps.values():
            for _dep in step.dependencies:
                # step depends on dep, so step has one more incoming edge
                in_degree[step.id] += 1

        groups = []
        remaining = set(self.steps.keys())

        while remaining:
            level = [step_id for step_id in remaining if in_degree[step_id] == 0]
            if not level:
                raise ValueError("Cycle detected in pipeline")
            groups.append(level)
            for step_id in level:
                remaining.remove(step_id)
                for other_step in self.steps.values():
                    if step_id in other_step.dependencies:
                        in_degree[other_step.id] -= 1

        return groups


@dataclass
class PipelineExecution:
    """Represents a single execution of a pipeline."""
    execution_id: str
    pipeline_id: str
    status: PipelineStatus
    started_at: str
    completed_at: str | None = None
    step_results: dict[str, StepResult] = field(default_factory=dict)
    total_cost_usd: float = 0.0
    error: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "execution_id": self.execution_id,
            "pipeline_id": self.pipeline_id,
            "status": self.status.value,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "step_results": {k: v.to_dict() for k, v in self.step_results.items()},
            "total_cost_usd": self.total_cost_usd,
            "error": self.error,
            "metadata": self.metadata,
        }


class CostTracker:
    """Tracks cumulative costs for budget enforcement."""

    def __init__(self, budget_policy: BudgetPolicy):
        self.budget_policy = budget_policy
        self.current_spend = 0.0
        self.step_costs: dict[str, float] = {}

    def record_cost(self, step_id: str, cost_usd: float) -> bool:
        """Record a cost. Always returns True (cost is always recorded).
        Use is_budget_exceeded() to check if budget was exceeded."""
        self.step_costs[step_id] = cost_usd
        self.current_spend += cost_usd
        return True

    def is_budget_exceeded(self) -> bool:
        return self.current_spend > self.budget_policy.hard_limit_usd

    def is_soft_limit_exceeded(self) -> bool:
        return self.current_spend > self.budget_policy.soft_limit_usd

    def get_remaining_budget(self) -> float:
        return max(0.0, self.budget_policy.hard_limit_usd - self.current_spend)

    def get_cost_breakdown(self) -> dict[str, float]:
        return dict(self.step_costs)


@dataclass(frozen=True, slots=True)
class BudgetPolicy:
    """Budget policy for pipeline execution."""
    soft_limit_usd: float
    hard_limit_usd: float
    warn_at_percent: float = 0.8
    alert_on_soft_limit: bool = True
    block_on_hard_limit: bool = True

    def __post_init__(self):
        if self.soft_limit_usd > self.hard_limit_usd:
            raise ValueError("Soft limit cannot exceed hard limit")


class ABTest:
    """A/B testing framework for pipeline variants."""

    def __init__(
        self,
        name: str,
        control_pipeline_id: str,
        variant_pipeline_id: str,
        traffic_split: float = 0.5,
        min_samples: int = 100,
        confidence_level: float = 0.95,
    ):
        self.name = name
        self.control_pipeline_id = control_pipeline_id
        self.variant_pipeline_id = variant_pipeline_id
        self.traffic_split = traffic_split
        self.min_samples = min_samples
        self.confidence_level = confidence_level
        self.control_executions = 0
        self.variant_executions = 0
        self.control_successes = 0
        self.variant_successes = 0

    def assign_variant(self) -> str:
        """Randomly assign a variant based on traffic split."""
        if random.random() < self.traffic_split:
            self.variant_executions += 1
            return self.variant_pipeline_id
        self.control_executions += 1
        return self.control_pipeline_id

    def record_result(self, variant: str, success: bool) -> None:
        """Record the result of an execution."""
        if variant == self.control_pipeline_id:
            self.control_executions += 1
            if success:
                self.control_successes += 1
        elif variant == self.variant_pipeline_id:
            self.variant_executions += 1
            if success:
                self.variant_successes += 1

    def get_results(self) -> dict[str, Any]:
        """Get statistical significance results."""
        import math

        # Handle case where no executions have been recorded
        if self.control_executions == 0 and self.variant_executions == 0:
            return {
                "control_rate": 0.0,
                "variant_rate": 0.0,
                "lift": 0.0,
                "z_score": 0.0,
                "p_value": 1.0,
                "significant": False,
                "control_executions": 0,
                "variant_executions": 0,
                "control_successes": 0,
                "variant_successes": 0,
            }

        control_rate = self.control_successes / self.control_executions if self.control_executions > 0 else 0
        variant_rate = self.variant_successes / self.variant_executions if self.variant_executions > 0 else 0

        # Two-proportion z-test
        total_executions = self.control_executions + self.variant_executions
        if total_executions == 0:
            pooled_rate = 0
        else:
            pooled_rate = (self.control_successes + self.variant_successes) / total_executions

        if pooled_rate == 0 or pooled_rate == 1:
            z_score = 0
        else:
            se = math.sqrt(pooled_rate * (1 - pooled_rate) * (1/self.control_executions + 1/self.variant_executions))
            z_score = (variant_rate - control_rate) / se if se > 0 else 0

        # Calculate p-value (two-tailed) using normal approximation
        # Using error function approximation for normal CDF
        def norm_cdf(x: float) -> float:
            return 0.5 * (1 + math.erf(x / math.sqrt(2)))

        p_value = 2 * (1 - norm_cdf(abs(z_score))) if abs(z_score) > 0 else 1.0

        return {
            "control_rate": control_rate,
            "variant_rate": variant_rate,
            "lift": (variant_rate - control_rate) / control_rate if control_rate > 0 else 0,
            "z_score": z_score,
            "p_value": p_value,
            "significant": p_value < (1 - self.confidence_level),
            "control_executions": self.control_executions,
            "variant_executions": self.variant_executions,
            "control_successes": self.control_successes,
            "variant_successes": self.variant_successes,
        }


class CanaryDeployment:
    """Canary deployment with gradual rollout."""

    def __init__(
        self,
        name: str,
        pipeline_id: str,
        rollout_steps: list[float] = None,
        step_duration_minutes: int = 60,
        success_threshold: float = 0.95,
        error_rate_threshold: float = 0.05,
    ):
        self.name = name
        self.pipeline_id = pipeline_id
        self.rollout_steps = rollout_steps or [0.1, 0.25, 0.5, 0.75, 1.0]
        self.step_duration_minutes = step_duration_minutes
        self.success_threshold = success_threshold
        self.error_rate_threshold = error_rate_threshold
        self.current_step = 0
        self.started_at: str | None = None
        self.step_started_at: str | None = None
        self.status = "pending"
        self.metrics: dict[str, Any] = {}

    def start(self) -> None:
        self.started_at = datetime.now(timezone.utc).isoformat()
        self.step_started_at = self.started_at
        self.status = "running"

    def advance_step(self, success_rate: float, error_rate: float) -> tuple[bool, str]:
        """Evaluate current step and advance if criteria met."""
        if self.current_step >= len(self.rollout_steps):
            self.status = "completed"
            return True, "Deployment completed"

        if success_rate >= self.success_threshold and error_rate <= self.error_rate_threshold:
            self.current_step += 1
            self.step_started_at = datetime.now(timezone.utc).isoformat()
            if self.current_step >= len(self.rollout_steps):
                self.status = "completed"
                return True, "Deployment completed successfully"
            return True, f"Advanced to step {self.current_step + 1} ({self.rollout_steps[self.current_step] * 100}%)"
        else:
            self.status = "failed"
            return False, f"Step failed: success_rate={success_rate}, error_rate={error_rate}"

    def get_current_traffic_percentage(self) -> float:
        if self.current_step < len(self.rollout_steps):
            return self.rollout_steps[self.current_step]
        return 1.0


class FeatureFlag:
    """Feature flag with gradual rollout support."""

    def __init__(
        self,
        name: str,
        enabled: bool = False,
        rollout_percentage: float = 0.0,
        targeting_rules: dict[str, Any] = None,
    ):
        self.name = name
        self.enabled = enabled
        self.rollout_percentage = rollout_percentage
        self.targeting_rules = targeting_rules or {}
        self.created_at = datetime.now(timezone.utc).isoformat()
        self.updated_at = self.created_at

    def is_enabled_for(self, context: dict[str, Any]) -> bool:
        """Check if flag is enabled for a given context."""
        if not self.enabled:
            return False

        # Check targeting rules
        for key, expected_value in self.targeting_rules.items():
            if context.get(key) != expected_value:
                return False

        # Check rollout percentage
        if self.rollout_percentage < 1.0:
            user_id = context.get("user_id", "")
            if not user_id:
                return False
            # Deterministic hash-based assignment (SHA-256 for consistency, not security)
            hash_input = f"{self.name}:{user_id}"
            hash_val = int(hashlib.sha256(hash_input.encode()).hexdigest(), 16)
            return (hash_val % 100) / 100 < self.rollout_percentage

        return True


class EnsembleVoter:
    """Multi-model ensemble with weighted voting."""

    def __init__(
        self,
        models: list[str],
        weights: list[float] | None = None,
        voting_strategy: str = "weighted_average",
    ):
        self.models = models
        self.weights = weights or [1.0 / len(models)] * len(models)
        if len(self.weights) != len(self.models):
            raise ValueError("Weights must match number of models")
        self.voting_strategy = voting_strategy

    def vote(self, predictions: dict[str, dict[str, Any]]) -> dict[str, Any]:
        """Aggregate predictions from multiple models."""
        if self.voting_strategy == "weighted_average":
            return self._weighted_average_vote(predictions)
        elif self.voting_strategy == "majority":
            return self._majority_vote(predictions)
        elif self.voting_strategy == "unanimous":
            return self._unanimous_vote(predictions)
        else:
            raise ValueError(f"Unknown voting strategy: {self.voting_strategy}")

    def _weighted_average_vote(self, predictions: dict[str, dict[str, Any]]) -> dict[str, Any]:
        """Weighted average of prediction scores."""
        score_sum = 0.0
        weight_sum = 0.0
        verdicts = {}

        for model, pred in predictions.items():
            if model not in self.models:
                continue
            weight = self.weights[self.models.index(model)]
            score = pred.get("score", 0.0)
            verdict = pred.get("verdict", "uncertain")
            score_sum += score * weight
            weight_sum += weight
            verdicts[verdict] = verdicts.get(verdict, 0) + weight

        final_score = score_sum / weight_sum if weight_sum > 0 else 0.0
        final_verdict = max(verdicts.items(), key=lambda x: x[1])[0] if verdicts else "uncertain"

        return {
            "score": final_score,
            "verdict": final_verdict,
            "confidence": max(verdicts.values()) / weight_sum if weight_sum > 0 else 0,
            "model_contributions": {m: predictions.get(m, {}).get("score", 0) * self.weights[self.models.index(m)] for m in self.models if m in predictions},
        }

    def _majority_vote(self, predictions: dict[str, dict[str, Any]]) -> dict[str, Any]:
        """Simple majority vote."""
        from collections import Counter
        verdicts = Counter(pred.get("verdict", "uncertain") for pred in predictions.values())
        most_common = verdicts.most_common(1)
        final_verdict = most_common[0][0] if most_common else "uncertain"
        confidence = most_common[0][1] / len(predictions) if most_common else 0

        return {
            "verdict": final_verdict,
            "confidence": confidence,
            "vote_counts": dict(verdicts),
        }

    def _unanimous_vote(self, predictions: dict[str, dict[str, Any]]) -> dict[str, Any]:
        """Unanimous vote - all must agree."""
        verdicts = [pred.get("verdict", "uncertain") for pred in predictions.values()]
        if len(set(verdicts)) == 1:
            return {"verdict": verdicts[0], "confidence": 1.0, "unanimous": True}
        return {"verdict": "uncertain", "confidence": 0.0, "unanimous": False}


@dataclass
class PipelineOrchestrator:
    """Main orchestrator for pipeline execution."""

    pipeline_dag: PipelineDAG
    budget_policy: BudgetPolicy
    ab_tests: dict[str, ABTest] = field(default_factory=dict)
    canary_deployments: dict[str, CanaryDeployment] = field(default_factory=dict)
    feature_flags: dict[str, FeatureFlag] = field(default_factory=dict)
    ensemble_voter: EnsembleVoter | None = None

    # Runtime state
    cost_tracker: CostTracker = field(init=False)
    execution_history: list[PipelineExecution] = field(default_factory=list)
    feature_flags: dict[str, FeatureFlag] = field(default_factory=dict)

    def __post_init__(self):
        self.cost_tracker = CostTracker(self.budget_policy)

    def add_ab_test(self, ab_test: ABTest) -> None:
        self.ab_tests[ab_test.name] = ab_test

    def add_canary_deployment(self, canary: CanaryDeployment) -> None:
        self.canary_deployments[canary.name] = canary

    def set_feature_flag(self, flag: FeatureFlag) -> None:
        self.feature_flags[flag.name] = flag

    def set_ensemble_voter(self, voter: EnsembleVoter) -> None:
        self.ensemble_voter = voter

    async def execute_pipeline(
        self,
        pipeline_id: str,
        input_data: Any,
        context: dict[str, Any] = None,
        execution_id: str | None = None,
    ) -> PipelineExecution:
        """Execute a pipeline with full orchestration."""
        execution_id = execution_id or str(uuid.uuid4())
        context = context or {}

        execution = PipelineExecution(
            execution_id=execution_id,
            pipeline_id=pipeline_id,
            status=PipelineStatus.RUNNING,
            started_at=datetime.now(timezone.utc).isoformat(),
        )

        # Check A/B test assignment
        pipeline_to_execute = pipeline_id
        ab_test = None
        for ab_test in self.ab_tests.values():
            if pipeline_id in [ab_test.control_pipeline_id, ab_test.variant_pipeline_id]:
                ab_test = ab_test
                pipeline_to_execute = ab_test.assign_variant()
                break

        execution.pipeline_id = pipeline_to_execute
        context["ab_test"] = ab_test.name if ab_test else None
        context["variant"] = pipeline_to_execute

        # Check feature flags
        for _flag_name, flag in self.feature_flags.items():
            if flag.is_enabled_for(context):
                context[f"feature_{flag.name}"] = True

        # Get execution order
        self.pipeline_dag.topological_order()

        # Execute steps in parallel groups
        parallel_groups = self.pipeline_dag.get_parallel_groups()

        execution.status = PipelineStatus.RUNNING

        try:
            for group in parallel_groups:
                # Execute all steps in this parallel group concurrently
                tasks = []
                for step_id in group:
                    step = self.pipeline_dag.steps[step_id]
                    tasks.append(self._execute_step(step, input_data, context))

                results = await asyncio.gather(*tasks, return_exceptions=True)

                for step_id, result in zip(group, results, strict=False):
                    if isinstance(result, Exception):
                        step_result = StepResult(
                            step_id=step_id,
                            status=StepStatus.FAILED,
                            error=str(result),
                        )
                    else:
                        step_result = result

                    execution.step_results[step_id] = step_result

                    # Record cost
                    self.cost_tracker.record_cost(step_id, step_result.cost_usd)
                    if self.cost_tracker.is_budget_exceeded() and self.budget_policy.block_on_hard_limit:
                        raise RuntimeError(f"Budget exceeded: {self.cost_tracker.current_spend}")

                    # Check if step failed and is required
                    step = self.pipeline_dag.steps[step_id]
                    if step_result.status == StepStatus.FAILED and step.required:
                        raise RuntimeError(f"Required step {step_id} failed: {step_result.error}")

            execution.status = PipelineStatus.COMPLETED
            execution.completed_at = datetime.now(timezone.utc).isoformat()

        except Exception as e:
            execution.status = PipelineStatus.FAILED
            execution.error = str(e)
            execution.completed_at = datetime.now(timezone.utc).isoformat()

        # Record A/B test result if applicable
        if ab_test:
            success = execution.status == PipelineStatus.COMPLETED
            ab_test.record_result(pipeline_to_execute, success)

        # Record canary metrics if applicable
        for canary in self.canary_deployments.values():
            canary.metrics[execution.execution_id] = {
                "status": execution.status.value,
                "duration_ms": sum(r.duration_ms for r in execution.step_results.values()),
                "cost_usd": execution.total_cost_usd,
            }

        execution.total_cost_usd = self.cost_tracker.current_spend
        self.execution_history.append(execution)

        return execution

    async def _execute_step(
        self,
        step: PipelineStep,
        input_data: Any,
        context: dict[str, Any],
    ) -> StepResult:
        """Execute a single pipeline step with retries."""
        start_time = time.time()
        last_error = None

        for attempt in range(step.retry_count + 1):
            try:
                # This is where actual step execution would happen
                # For now, return a mock result
                result = await self._run_step_logic(step, input_data, context)

                return StepResult(
                    step_id=step.id,
                    status=StepStatus.COMPLETED,
                    output=result,
                    duration_ms=(time.time() - start_time) * 1000,
                    cost_usd=step.cost_estimate_usd,
                )
            except Exception as e:
                last_error = e
                if attempt < step.retry_count:
                    await asyncio.sleep(step.retry_delay * (2 ** attempt))  # Exponential backoff
                else:
                    break

        return StepResult(
            step_id=step.id,
            status=StepStatus.FAILED,
            error=str(last_error) if last_error else "Unknown error",
            duration_ms=(time.time() - start_time) * 1000,
            cost_usd=step.cost_estimate_usd,
        )

    async def _run_step_logic(self, step: PipelineStep, input_data: Any, context: dict[str, Any]) -> Any:
        """Override this method to implement actual step logic."""
        # This is a placeholder - actual implementation would call detector, etc.
        return {"status": "completed", "step": step.id}

    def get_execution_history(self, limit: int = 100) -> list[PipelineExecution]:
        return self.execution_history[-limit:]

    def get_cost_report(self) -> dict[str, Any]:
        return {
            "total_spend_usd": self.cost_tracker.current_spend,
            "budget_remaining": self.cost_tracker.get_remaining_budget(),
            "soft_limit_exceeded": self.cost_tracker.is_soft_limit_exceeded(),
            "hard_limit_exceeded": self.cost_tracker.is_budget_exceeded(),
            "step_costs": self.cost_tracker.get_cost_breakdown(),
            "budget_policy": {
                "soft_limit_usd": self.budget_policy.soft_limit_usd,
                "hard_limit_usd": self.budget_policy.hard_limit_usd,
            },
        }

    def get_ab_test_results(self, test_name: str) -> dict[str, Any] | None:
        if test_name in self.ab_tests:
            return self.ab_tests[test_name].get_results()
        return None

    def get_canary_status(self, canary_name: str) -> dict[str, Any] | None:
        if canary_name in self.canary_deployments:
            canary = self.canary_deployments[canary_name]
            return {
                "name": canary.name,
                "status": canary.status,
                "current_traffic": canary.get_current_traffic_percentage(),
                "current_step": canary.current_step,
                "total_steps": len(canary.rollout_steps),
                "metrics": canary.metrics,
            }
        return None


def create_pipeline_orchestrator(
    steps: list[PipelineStep],
    budget_policy: BudgetPolicy,
    pipeline_id: str = "default",
) -> PipelineOrchestrator:
    """Factory function to create a pipeline orchestrator."""
    dag = PipelineDAG(steps)
    return PipelineOrchestrator(
        pipeline_dag=dag,
        budget_policy=budget_policy,
    )


# ============================================================
# Convenience Functions
# ============================================================

def create_default_pipeline(
    detector_steps: list[PipelineStep],
    budget_usd: float = 1.0,
) -> PipelineOrchestrator:
    """Create a standard detection pipeline with budget."""
    budget = BudgetPolicy(
        soft_limit_usd=budget_usd * 0.8,
        hard_limit_usd=budget_usd,
    )
    return create_pipeline_orchestrator(detector_steps, budget)


# ============================================================
# Module Exports
# ============================================================

__all__ = [
    "PipelineStep",
    "PipelineStatus",
    "StepStatus",
    "PipelineDAG",
    "PipelineExecution",
    "StepResult",
    "CostTracker",
    "BudgetPolicy",
    "ABTest",
    "CanaryDeployment",
    "FeatureFlag",
    "EnsembleVoter",
    "PipelineOrchestrator",
    "StepResult",
    "BudgetPolicy",
    "CostTracker",
    "create_pipeline_orchestrator",
]
