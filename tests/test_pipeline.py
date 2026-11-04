"""Tests for Pipeline Orchestrator."""

from __future__ import annotations

import pytest

from textforensics.pipeline import (
    ABTest,
    BudgetPolicy,
    CanaryDeployment,
    CostTracker,
    EnsembleVoter,
    FeatureFlag,
    PipelineDAG,
    PipelineExecution,
    PipelineOrchestrator,
    PipelineStatus,
    PipelineStep,
    StepResult,
    StepStatus,
    create_pipeline_orchestrator,
)


class TestPipelineStep:
    def test_step_creation(self):
        step = PipelineStep(
            id="step1",
            name="Test Step",
            dependencies=["step0"],
            timeout_seconds=60.0,
            retry_count=2,
            cost_estimate_usd=0.01,
        )
        assert step.id == "step1"
        assert step.dependencies == ["step0"]
        assert step.timeout_seconds == 60.0

    def test_step_serialization(self):
        step = PipelineStep(
            id="step1",
            name="Test",
            dependencies=["step0"],
        )
        d = step.to_dict()
        assert d["id"] == "step1"
        assert d["dependencies"] == ["step0"]


class TestPipelineDAG:
    def test_dag_creation(self):
        steps = [
            PipelineStep(id="step1", name="Step 1", dependencies=[]),
            PipelineStep(id="step2", name="Step 2", dependencies=["step1"]),
            PipelineStep(id="step3", name="Step 3", dependencies=["step1"]),
            PipelineStep(id="step4", name="Step 4", dependencies=["step2", "step3"]),
        ]
        dag = PipelineDAG(steps)
        assert len(dag.steps) == 4

    def test_invalid_dependency(self):
        steps = [
            PipelineStep(id="step1", name="Step 1", dependencies=["nonexistent"]),
        ]
        with pytest.raises(ValueError, match="non-existent step"):
            PipelineDAG(steps)

    def test_cycle_detection(self):
        steps = [
            PipelineStep(id="step1", name="Step 1", dependencies=["step2"]),
            PipelineStep(id="step2", name="Step 2", dependencies=["step1"]),
        ]
        with pytest.raises(ValueError, match="cycles"):
            PipelineDAG(steps)

    def test_topological_order(self):
        steps = [
            PipelineStep(id="step1", name="Step 1", dependencies=[]),
            PipelineStep(id="step2", name="Step 2", dependencies=["step1"]),
            PipelineStep(id="step3", name="Step 3", dependencies=["step1"]),
            PipelineStep(id="step4", name="Step 4", dependencies=["step2", "step3"]),
        ]
        dag = PipelineDAG(steps)
        order = dag.topological_order()
        assert order[0] == "step1"
        assert order[-1] == "step4"
        assert len(order) == 4

    def test_parallel_groups(self):
        steps = [
            PipelineStep(id="step1", name="Step 1", dependencies=[]),
            PipelineStep(id="step2", name="Step 2", dependencies=["step1"]),
            PipelineStep(id="step3", name="Step 3", dependencies=["step1"]),
            PipelineStep(id="step4", name="Step 4", dependencies=["step2", "step3"]),
        ]
        dag = PipelineDAG(steps)
        groups = dag.get_parallel_groups()
        assert len(groups) == 3
        assert groups[0] == ["step1"]
        assert set(groups[1]) == {"step2", "step3"}
        assert groups[2] == ["step4"]


class TestPipelineExecution:
    def test_execution_creation(self):
        exec_obj = PipelineExecution(
            execution_id="exec1",
            pipeline_id="pipe1",
            status=PipelineStatus.RUNNING,
            started_at="2024-01-01T00:00:00Z",
        )
        assert exec_obj.execution_id == "exec1"
        assert exec_obj.status == PipelineStatus.RUNNING

    def test_serialization(self):
        exec_obj = PipelineExecution(
            execution_id="exec1",
            pipeline_id="pipe1",
            status=PipelineStatus.COMPLETED,
            started_at="2024-01-01T00:00:00Z",
            completed_at="2024-01-01T00:01:00Z",
            total_cost_usd=0.05,
        )
        d = exec_obj.to_dict()
        assert d["execution_id"] == "exec1"
        assert d["status"] == "completed"
        assert d["total_cost_usd"] == 0.05


class TestStepResult:
    def test_result_creation(self):
        result = StepResult(
            step_id="step1",
            status=StepStatus.COMPLETED,
            output={"result": "ok"},
            duration_ms=100.0,
            cost_usd=0.01,
        )
        assert result.step_id == "step1"
        assert result.status == StepStatus.COMPLETED

    def test_serialization(self):
        result = StepResult(
            step_id="step1",
            status=StepStatus.FAILED,
            error="Something went wrong",
            duration_ms=100.0,
        )
        d = result.to_dict()
        assert d["status"] == "failed"
        assert d["error"] == "Something went wrong"


class TestBudgetPolicy:
    def test_budget_creation(self):
        policy = BudgetPolicy(soft_limit_usd=0.80, hard_limit_usd=1.00)
        assert policy.soft_limit_usd == 0.80
        assert policy.hard_limit_usd == 1.00

    def test_invalid_budget(self):
        with pytest.raises(ValueError):
            BudgetPolicy(soft_limit_usd=1.0, hard_limit_usd=0.5)


class TestCostTracker:
    def test_cost_tracking(self):
        policy = BudgetPolicy(soft_limit_usd=0.80, hard_limit_usd=1.00)
        tracker = CostTracker(policy)

        assert tracker.record_cost("step1", 0.1) is True
        assert tracker.current_spend == 0.1
        assert tracker.is_budget_exceeded() is False

    def test_budget_exceeded(self):
        policy = BudgetPolicy(soft_limit_usd=0.50, hard_limit_usd=1.00)
        tracker = CostTracker(policy)

        assert tracker.record_cost("step1", 0.60) is True
        assert tracker.is_budget_exceeded() is False  # Not over hard limit

        assert tracker.record_cost("step2", 0.50) is True
        assert tracker.is_budget_exceeded() is True  # 1.10 > 1.00

    def test_soft_limit(self):
        policy = BudgetPolicy(soft_limit_usd=0.50, hard_limit_usd=1.00)
        tracker = CostTracker(policy)

        tracker.record_cost("step1", 0.60)
        assert tracker.is_soft_limit_exceeded() is True


class TestPipelineOrchestrator:
    @pytest.mark.asyncio
    async def test_basic_execution(self):
        steps = [
            PipelineStep(id="step1", name="Step 1", cost_estimate_usd=0.01),
            PipelineStep(id="step2", name="Step 2", dependencies=["step1"], cost_estimate_usd=0.01),
        ]
        budget = BudgetPolicy(soft_limit_usd=0.5, hard_limit_usd=1.0)
        orchestrator = create_pipeline_orchestrator(steps, budget)

        result = await orchestrator.execute_pipeline("test_pipeline", "test input")
        assert result.status == PipelineStatus.COMPLETED
        assert result.total_cost_usd >= 0

    @pytest.mark.asyncio
    async def test_budget_exceeded(self):
        steps = [
            PipelineStep(id="step1", name="Step 1", cost_estimate_usd=1.0),
        ]
        budget = BudgetPolicy(soft_limit_usd=0.1, hard_limit_usd=0.5)
        orchestrator = create_pipeline_orchestrator(steps, budget)

        result = await orchestrator.execute_pipeline("test", "input")
        # Should fail due to budget exceeded
        assert result.status == PipelineStatus.FAILED

    @pytest.mark.asyncio
    async def test_step_failure(self):
        [
            PipelineStep(id="step1", name="Failing Step", cost_estimate_usd=0.01),
        ]

        # Create orchestrator with a step that will fail
        class FailingOrchestrator(PipelineOrchestrator):
            async def _run_step_logic(self, step, input_data, context):
                raise RuntimeError("Simulated failure")

        budget = BudgetPolicy(soft_limit_usd=1.0, hard_limit_usd=1.0)
        dag = PipelineDAG([
            PipelineStep(id="step1", name="Failing", cost_estimate_usd=0.01)
        ])
        orchestrator = PipelineOrchestrator(dag, budget)
        orchestrator._run_step_logic = lambda step, input_data, context: (_ for _ in ()).throw(RuntimeError("Simulated failure"))

        result = await orchestrator.execute_pipeline("test", "input")
        assert result.status == PipelineStatus.FAILED


class TestABTest:
    def test_assignment(self):
        test = ABTest("test", "control", "variant", traffic_split=0.5)
        control_count = 0
        variant_count = 0
        for _ in range(1000):
            variant = test.assign_variant()
            if variant == "control":
                control_count += 1
            else:
                variant_count += 1
        # Should be roughly 50/50
        assert 400 < control_count < 600

    def test_result_recording(self):
        test = ABTest("test", "control", "variant")
        test.record_result("control", True)
        test.record_result("control", False)
        test.record_result("variant", True)
        test.record_result("variant", True)

        results = test.get_results()
        assert results["control_executions"] == 2
        assert results["variant_executions"] == 2
        assert results["control_successes"] == 1
        assert results["variant_successes"] == 2


class TestCanaryDeployment:
    def test_canary_progression(self):
        canary = CanaryDeployment("test", "pipeline1", rollout_steps=[0.1, 0.5, 1.0])
        canary.start()

        assert canary.get_current_traffic_percentage() == 0.1

        # Advance with good metrics
        advanced, msg = canary.advance_step(0.99, 0.01)
        assert advanced is True
        assert canary.current_step == 1
        assert canary.get_current_traffic_percentage() == 0.5

        # Complete rollout
        canary.advance_step(0.99, 0.01)
        canary.advance_step(0.99, 0.01)
        assert canary.status == "completed"

    def test_canary_failure(self):
        canary = CanaryDeployment("test", "pipeline", rollout_steps=[0.1, 0.5, 1.0])
        canary.start()
        # Fail the first step
        advanced, msg = canary.advance_step(0.5, 0.5)
        assert advanced is False
        assert canary.status == "failed"


class TestFeatureFlag:
    def test_feature_flag_basic(self):
        flag = FeatureFlag("new_feature", enabled=True, rollout_percentage=0.5)
        assert flag.is_enabled_for({"user_id": "user1"}) in (True, False)

    def test_feature_flag_targeting(self):
        flag = FeatureFlag(
            "premium",
            enabled=True,
            targeting_rules={"tier": "premium"},
            rollout_percentage=1.0,
        )
        assert flag.is_enabled_for({"user_id": "user1", "tier": "premium"}) is True
        assert flag.is_enabled_for({"user_id": "user2", "tier": "free"}) is False

    def test_disabled_flag(self):
        flag = FeatureFlag("disabled_feature", enabled=False)
        assert flag.is_enabled_for({"user_id": "user1"}) is False


class TestEnsembleVoter:
    def test_weighted_average_vote(self):
        voter = EnsembleVoter(
            models=["model1", "model2", "model3"],
            weights=[0.5, 0.3, 0.2],
            voting_strategy="weighted_average",
        )
        predictions = {
            "model1": {"score": 0.9, "verdict": "ai"},
            "model2": {"score": 0.6, "verdict": "ai"},
            "model3": {"score": 0.3, "verdict": "human"},
        }
        result = voter.vote(predictions)
        assert result["verdict"] == "ai"
        assert 0.5 < result["score"] < 0.8

    def test_majority_vote(self):
        voter = EnsembleVoter(models=["m1", "m2", "m3"], voting_strategy="majority")
        predictions = {
            "m1": {"verdict": "ai"},
            "m2": {"verdict": "ai"},
            "m3": {"verdict": "human"},
        }
        result = voter.vote(predictions)
        assert result["verdict"] == "ai"
        assert result["confidence"] == 2/3

    def test_unanimous_vote(self):
        voter = EnsembleVoter(models=["m1", "m2"], voting_strategy="unanimous")
        predictions = {"m1": {"verdict": "ai"}, "m2": {"verdict": "ai"}}
        result = voter.vote(predictions)
        assert result["verdict"] == "ai"
        assert result["unanimous"] is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
