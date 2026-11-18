//! `Self-host images` — builds the images the self-host compose stack pulls
//! (`selfhost/docker-compose.yml`, built from the sources `docker-compose.build.yml`
//! names) and pushes them to the repository owner's GitHub Container
//! Registry. Runs on pushes to `main`; any other branch publishes only when
//! dispatched by hand, under its own (sanitized) branch-name tag, so it never
//! replaces the `main` images. Generated into `selfhost-images.yml`.
//!
//! GitHub-hosted runners: the job only needs Docker, and forks have no
//! Namespace profiles. Layers are cached in the Actions cache per image.

use std::collections::HashMap;

use gh_workflow::{
    Concurrency, Event, Expression, Job, Level, Permissions, Push, Run, Step, Use, Workflow,
    WorkflowDispatch, WorkflowDispatchInput,
};

use crate::workflows::steps;

/// The branch whose pushes publish the `main` images compose pulls by default.
pub const BRANCH: &str = "main";

/// One published image: `<owner registry>/macro-selfhost-<name>`.
pub struct Image {
    pub name: &'static str,
    pub context: &'static str,
    pub dockerfile: &'static str,
    pub target: Option<&'static str>,
}

/// The Dockerfile both Rust images build from.
const RUST_DOCKERFILE: &str = "selfhost/docker/rust.Dockerfile";
/// Parallel rustc jobs for that build. The hosted runner's 16 GB memory and
/// 4 vCPUs failed at the default (every core); two stays within memory.
const RUST_CARGO_BUILD_JOBS: u32 = 2;

/// The two images built from the Rust workspace share one builder stage.
pub const RUST: &[Image] = &[
    Image {
        name: "services",
        context: ".",
        dockerfile: RUST_DOCKERFILE,
        target: Some("services"),
    },
    Image {
        name: "init",
        context: ".",
        dockerfile: RUST_DOCKERFILE,
        target: Some("init"),
    },
];

pub const GATEWAY: &[Image] = &[Image {
    name: "gateway",
    context: ".",
    dockerfile: "selfhost/docker/gateway.Dockerfile",
    target: None,
}];

pub const WORKERS: &[Image] = &[
    Image {
        name: "sync",
        context: ".",
        dockerfile: "docker/sync-service.Dockerfile",
        target: None,
    },
    Image {
        name: "lexical",
        context: ".",
        dockerfile: "docker/lexical-service.Dockerfile",
        target: None,
    },
    Image {
        name: "websocket",
        context: ".",
        dockerfile: "docker/websocket-service.Dockerfile",
        target: None,
    },
    Image {
        name: "ai-editing",
        context: ".",
        dockerfile: "selfhost/docker/ai-editing-worker.Dockerfile",
        target: None,
    },
    Image {
        name: "opensearch",
        context: "infra/local/opensearch",
        dockerfile: "infra/local/opensearch/Dockerfile",
        target: None,
    },
];

/// Build the workflow.
pub fn selfhost_images() -> Workflow {
    Workflow::new("Self-host images")
        .on(Event::default()
            .push(Push::default().add_branch(BRANCH))
            .workflow_dispatch(dispatch()))
        .permissions(Permissions::default().contents(Level::Read))
        .concurrency(
            Concurrency::new(Expression::new("${{ github.workflow }}-${{ github.ref }}"))
                .cancel_in_progress(true),
        )
        .add_job("rust", job("rust", "Rust services and init", RUST))
        .add_job("gateway", job("gateway", "Gateway and web app", GATEWAY))
        .add_job("workers", job("workers", "Workers and search", WORKERS))
}

/// A manual run picks which image groups to rebuild (all by default), so a
/// web-only change can skip the long Rust build. Pushes always build every
/// group. One string input: `WorkflowDispatch` keeps inputs in a `HashMap`,
/// whose order would make the generated file unstable.
fn dispatch() -> WorkflowDispatch {
    let images = WorkflowDispatchInput {
        description: "Image groups to build, comma-separated: rust, gateway, workers".into(),
        required: false,
        input_type: "string".into(),
        default: Some("rust,gateway,workers".into()),
    };
    WorkflowDispatch {
        inputs: HashMap::from([("images".into(), images)]),
    }
}

fn job(group: &str, name: &str, images: &[Image]) -> Job {
    let job = Job::default()
        .name(name)
        .cond(Expression::new(format!(
            "github.event_name != 'workflow_dispatch' || contains(inputs.images, '{group}')"
        )))
        .runs_on("ubuntu-latest")
        .timeout_minutes(360u32)
        .permissions(
            Permissions::default()
                .contents(Level::Read)
                .packages(Level::Write),
        )
        .add_step(steps::checkout(false, false))
        .add_step(monitor_start())
        .add_step(docker_storage())
        .add_step(free_disk())
        .add_step(image_prefix())
        .add_step(setup_buildx())
        .add_step(login());
    images
        .iter()
        .fold(job, |job, image| job.add_step(build_push(image)))
        .add_step(monitor_report())
}

/// The hosted runner's ~14 GB of free disk does not fit a release build of
/// the Rust services; drop the preinstalled toolchains this job never uses.
fn free_disk() -> Step<Run> {
    Step::new("Free disk space").run(indoc::indoc! {r#"
        sudo rm -rf /usr/share/dotnet /usr/local/lib/android /opt/ghc /opt/hostedtoolcache/CodeQL
        docker system prune -af
        df -h /
    "#})
}

/// Docker's data root sits on the hosted runner's ~14 GB root disk, which the
/// Rust build fills; `/mnt` has ~70 GB free. Moves the data root there before
/// buildx creates its builder, merging into any existing daemon.json.
fn docker_storage() -> Step<Run> {
    Step::new("Move Docker storage to /mnt").run(indoc::indoc! {r#"
        df -h / /mnt
        sudo systemctl stop docker.socket docker
        sudo mkdir -p /mnt/docker
        config='{"data-root": "/mnt/docker"}'
        if [ -s /etc/docker/daemon.json ]; then
          config="$(sudo jq --arg root /mnt/docker '. + {"data-root": $root}' /etc/docker/daemon.json)"
        fi
        echo "$config" | sudo tee /etc/docker/daemon.json >/dev/null
        sudo systemctl start docker
        docker info --format 'Docker root: {{.DockerRootDir}}'
        df -h / /mnt
    "#})
}

/// A background loop records disk and memory every minute in a file, so a runner
/// that dies mid-build still shows its state. It stops after six hours, or when
/// `monitor_report` kills it. Its stdio goes to the file: a background process
/// holding the step's stdout can stall the step.
fn monitor_start() -> Step<Run> {
    Step::new("Start resource monitor").run(indoc::indoc! {r#"
        log=/tmp/resource-monitor.log
        : > "$log"
        (
          end=$((SECONDS + 21600))
          while [ "$SECONDS" -lt "$end" ]; do
            { date; df -h / /mnt; free -m; } || true
            sleep 60
          done
        ) >> "$log" 2>&1 </dev/null &
        echo "$!" > /tmp/resource-monitor.pid
    "#})
}

/// Runs even when a build fails or the job is cancelled: stops the monitor and
/// prints its log.
fn monitor_report() -> Step<Run> {
    let mut step = Step::new("Print resource log").run(indoc::indoc! {r#"
        if [ -f /tmp/resource-monitor.pid ]; then
          pid="$(cat /tmp/resource-monitor.pid)"
          pkill -P "$pid" 2>/dev/null || true
          kill "$pid" 2>/dev/null || true
        fi
        cat /tmp/resource-monitor.log 2>/dev/null || echo "no resource log"
    "#});
    // Runs even on failure or cancellation.
    step = step.if_condition(Expression::new("always()"));
    step
}

/// GHCR names must be lowercase; owners need not be. A ref name may hold
/// characters a tag cannot (`/` in `feature/x`), so the tag is sanitized.
fn image_prefix() -> Step<Run> {
    Step::new("Image prefix")
        .run(indoc::indoc! {r#"
            echo "prefix=ghcr.io/${GITHUB_REPOSITORY_OWNER,,}/macro-selfhost" >> "$GITHUB_OUTPUT"
            tag="$(printf '%s' "$GITHUB_REF_NAME" | tr -c 'A-Za-z0-9_.-' '-' | cut -c1-128)"
            echo "tag=$tag" >> "$GITHUB_OUTPUT"
        "#})
        .id("prefix")
}

fn setup_buildx() -> Step<Use> {
    Step::new("Set up Docker Buildx").uses(
        "docker",
        "setup-buildx-action",
        "f87e5991a6d7451dcb8d9637bfbc97413f497069",
    ) // v4.4.1
}

fn login() -> Step<Use> {
    Step::new("Log in to GHCR")
        .uses(
            "docker",
            "login-action",
            "8aa5831fb8d48d8f76594c7ddde61ae58019f550",
        ) // v4.8.0
        .add_with(("registry", "ghcr.io"))
        .add_with(("username", "${{ github.actor }}"))
        .add_with(("password", "${{ secrets.GITHUB_TOKEN }}"))
}

fn build_push(image: &Image) -> Step<Use> {
    let name = image.name;
    let repository = format!("${{{{ steps.prefix.outputs.prefix }}}}-{name}");
    let scope = image.dockerfile.replace('/', "-");
    let step = Step::new(format!("Build and push {name}"))
        .uses(
            "docker",
            "build-push-action",
            "c3c9e263c25d99ce0380d002d59b67737d91b0dc",
        ) // v7.4.0
        .add_with(("context", image.context))
        .add_with(("file", image.dockerfile))
        .add_with(("platforms", "linux/amd64"))
        .add_with(("push", true))
        .add_with((
            "tags",
            format!(
                "{repository}:${{{{ steps.prefix.outputs.tag }}}}\n{repository}:sha-${{{{ github.sha }}}}"
            ),
        ))
        // One scope per Dockerfile, so the init image reuses the services
        // image's Rust build stage instead of compiling it again.
        .add_with(("cache-from", format!("type=gha,scope={scope}")))
        .add_with(("cache-to", format!("type=gha,scope={scope},mode=max")));
    let step = match image.target {
        Some(target) => step.add_with(("target", target)),
        None => step,
    };
    // Init reuses the services build stage, so both pass the same args to hit its cache.
    if image.dockerfile == RUST_DOCKERFILE {
        step.add_with((
            "build-args",
            format!("CARGO_BUILD_JOBS={RUST_CARGO_BUILD_JOBS}"),
        ))
    } else {
        step
    }
}
