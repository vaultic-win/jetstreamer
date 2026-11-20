//! The actual production phase order, shared by native adapters and injected
//! interruption tests. Test faults are not CLI, environment or plan features.
use super::*;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ParkStep {
    Prepare,
    VerifyBlob,
    RevalidateSource,
    PublishManifest,
    PersistCustody,
}
pub(super) trait ParkOperations {
    async fn step(&mut self, step: ParkStep) -> Result<()>;
    fn checkpoint(&mut self, _step: ParkStep) -> Result<()> {
        Ok(())
    }
}
pub(super) async fn park(ops: &mut impl ParkOperations) -> Result<()> {
    for step in [
        ParkStep::Prepare,
        ParkStep::VerifyBlob,
        ParkStep::RevalidateSource,
        ParkStep::PublishManifest,
        ParkStep::PersistCustody,
    ] {
        ops.step(step).await?;
        ops.checkpoint(step)?;
    }
    Ok(())
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RestoreStep {
    Prepare,
    Download,
    Metadata,
    VerifyBody,
    VerifyRemote,
    VerifyCapacity,
    PersistReceipt,
}
pub(super) trait RestoreOperations {
    async fn step(&mut self, step: RestoreStep) -> Result<()>;
    fn checkpoint(&mut self, _step: RestoreStep) -> Result<()> {
        Ok(())
    }
}
pub(super) async fn restore(ops: &mut impl RestoreOperations) -> Result<()> {
    for step in [
        RestoreStep::Prepare,
        RestoreStep::Download,
        RestoreStep::Metadata,
        RestoreStep::VerifyBody,
        RestoreStep::VerifyRemote,
        RestoreStep::VerifyCapacity,
        RestoreStep::PersistReceipt,
    ] {
        ops.step(step).await?;
        ops.checkpoint(step)?;
    }
    Ok(())
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct RetireState {
    pub source: bool,
    pub quarantine: bool,
    pub intent: bool,
    pub verified: bool,
    pub unlink: bool,
    pub complete: bool,
}
impl RetireState {
    pub(super) fn validate(self) -> Result<()> {
        ensure!(
            !(self.source && self.quarantine),
            "both original and quarantine names occupied"
        );
        ensure!(
            !self.unlink || self.verified,
            "unlink intent lacks quarantine verification"
        );
        ensure!(
            !self.verified || self.intent,
            "quarantine lacks retirement intent"
        );
        if self.complete {
            ensure!(
                !self.source && !self.quarantine && self.intent && self.verified && self.unlink,
                "completed namespace differs"
            );
        } else if !self.intent {
            ensure!(
                self.source && !self.quarantine && !self.verified && !self.unlink,
                "fresh retirement requires exact original only"
            );
        } else if self.source {
            ensure!(
                !self.verified && !self.unlink,
                "original namespace reappeared after quarantine"
            );
        } else if !self.quarantine {
            ensure!(
                self.verified && self.unlink,
                "missing private bytes without durable unlink intent"
            );
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RetireStep {
    VerifyComplete,
    Inspect,
    HashOriginal,
    CheckOnly,
    Intent,
    ReconcileIntent,
    BeforeRename,
    Rename,
    HashQuarantine,
    QuarantineProof,
    UnlinkIntent,
    BeforeUnlink,
    Unlink,
    VerifyChain,
    Complete,
}
pub(super) trait RetireOperations {
    fn state(&self) -> Result<RetireState>;
    async fn step(&mut self, step: RetireStep) -> Result<()>;
    fn checkpoint(&mut self, _step: RetireStep) -> Result<()> {
        Ok(())
    }
}
async fn retirement_step(ops: &mut impl RetireOperations, step: RetireStep) -> Result<()> {
    ops.step(step).await?;
    ops.checkpoint(step)
}
pub(super) async fn retire(ops: &mut impl RetireOperations, check: bool) -> Result<()> {
    let state = ops.state()?;
    state.validate()?;
    if state.complete {
        return retirement_step(ops, RetireStep::VerifyComplete).await;
    }
    if !state.source && !state.quarantine {
        // Unlink already committed. Reconcile its exact durable chain; there
        // are no bytes left to mutate or a live inode to reinterpret.
        retirement_step(ops, RetireStep::ReconcileIntent).await?;
        retirement_step(ops, RetireStep::VerifyChain).await?;
        if check {
            return retirement_step(ops, RetireStep::CheckOnly).await;
        }
        return retirement_step(ops, RetireStep::Complete).await;
    }
    retirement_step(ops, RetireStep::Inspect).await?;
    if !state.intent {
        retirement_step(ops, RetireStep::HashOriginal).await?;
        if check {
            return retirement_step(ops, RetireStep::CheckOnly).await;
        }
        retirement_step(ops, RetireStep::Intent).await?;
    } else {
        retirement_step(ops, RetireStep::ReconcileIntent).await?;
        if check {
            return retirement_step(ops, RetireStep::CheckOnly).await;
        }
    }
    retirement_step(ops, RetireStep::BeforeRename).await?;
    if state.source {
        retirement_step(ops, RetireStep::Rename).await?;
    }
    if ops.state()?.quarantine {
        for step in [
            RetireStep::HashQuarantine,
            RetireStep::QuarantineProof,
            RetireStep::UnlinkIntent,
            RetireStep::BeforeUnlink,
            RetireStep::Unlink,
        ] {
            retirement_step(ops, step).await?;
        }
    } else {
        retirement_step(ops, RetireStep::VerifyChain).await?;
    }
    retirement_step(ops, RetireStep::Complete).await
}
