#!/usr/bin/env python3
"""Build or update a Graphify repository map and print concise agent guidance.

Orientation loading and formatting live in devel/graphify_context_lib.py; this
script owns the command line, the Graphify subprocess lifecycle, and main().
"""

# Standard Library
import os
import sys
import json
import shutil
import pathlib
import argparse
import subprocess

# local repo modules
import graphify_docs_lib
import graphify_context_lib
import graphify_prune_tests


CLAUDE_LABEL_MODEL = "sonnet"
OLLAMA_MODEL = "qwen2.5-coder:7b-instruct"
GRAPHIFY_PACKAGE = "graphifyy[ollama,sql,terraform]"
LABEL_BACKEND = "claude-cli"
OLLAMA_BACKEND = "ollama"
MODE_AUTO = "auto"
MODE_FRESH = "fresh"
MODE_UPDATE = "update"
MODE_CONTEXT = "context"
MODE_REFLECT = "reflect"
MODE_PAGE = "page"
COLLAPSED_EDGE_FIELD = "directed_same_endpoint_collapsed_edges"


#============================================


def build_parser() -> argparse.ArgumentParser:
	"""Build the documented Graphify command-line parser."""
	manager_context_path = (
		f"{graphify_context_lib.OUTPUT_DIR_NAME}/"
		f"{graphify_context_lib.MANAGER_CONTEXT_FILE_NAME}"
	)
	help_epilog = (
		"How it works:\n"
		f"  With no mode, update {graphify_context_lib.OUTPUT_DIR_NAME}/"
		f"{graphify_context_lib.GRAPH_FILE_NAME} when it exists; otherwise extract a\n"
		"  fresh graph. Updates use Graphify's code-only fast path by default. Adding\n"
		"  --include-docs to --update incrementally extracts changed code and semantic inputs,\n"
		"  then refreshes community labels. Fresh builds upgrade Graphify, force extraction,\n"
		"  fully label, and benchmark. --include-docs includes nonignored document, paper, and\n"
		f"  image inputs. Claude CLI uses {CLAUDE_LABEL_MODEL}; --ollama selects the model for\n"
		"  extraction and labels. Context prints orientation without running\n"
		"  Graphify. Before the first map exists, context prints this help instead.\n"
		"  Incremental builds name only unlabeled communities; fresh builds relabel fully\n"
		"  and report edge fidelity. --force-shrink lets an update write a smaller graph\n"
		"  after code was deleted. --deep refines semantic extraction. --global also merges\n"
		"  this repository into the shared cross-repository graph. Reflect aggregates\n"
		"  outcomes saved with graphify save-result into a lessons file.\n"
		"\n"
		"Examples:\n"
		"  %(prog)s              # automatically choose fresh or update\n"
		"  %(prog)s --fresh      # upgrade, extract, fully label, and benchmark\n"
		"  %(prog)s --fresh --include-docs  # include nonignored semantic inputs\n"
		"  %(prog)s --update     # update, or run the fresh path when no graph exists\n"
		"  %(prog)s --update --include-docs  # incrementally refresh semantic inputs\n"
		"  %(prog)s --fresh --ollama  # use Ollama instead of Claude CLI\n"
		"  %(prog)s --update --force-shrink  # accept a smaller graph after deleting code\n"
		"  %(prog)s --fresh --include-docs --deep  # aggressive inferred-edge extraction\n"
		"  %(prog)s --fresh --global  # also register in the cross-repository graph\n"
		"  %(prog)s --context    # print orientation without rebuilding\n"
		"  %(prog)s --reflect    # aggregate saved query outcomes into lessons\n"
		"\n"
		f"Fresh-build setup: pip upgrades {GRAPHIFY_PACKAGE}.\n"
		f"Label backend: Claude CLI with {CLAUDE_LABEL_MODEL}; --ollama pulls {OLLAMA_MODEL}.\n"
		"Run graphify benchmark directly for measurements outside a fresh build.\n"
		f"Manager context: {manager_context_path}"
	)
	# ASVS 2.1.1 and 2.2.1: document the accepted modes and validate against an allowlist.
	parser = argparse.ArgumentParser(
		description=(
			"Build or update a Graphify repository map, then print concise agent "
			"orientation."
		),
		epilog=help_epilog,
		formatter_class=argparse.RawDescriptionHelpFormatter,
	)
	mode_group = parser.add_mutually_exclusive_group()
	mode_group.add_argument(
		"-F", "--fresh",
		dest="mode",
		action="store_const",
		const=MODE_FRESH,
		help="force a fresh graphify extract, even when a graph already exists",
	)
	mode_group.add_argument(
		"-U", "--update",
		dest="mode",
		action="store_const",
		const=MODE_UPDATE,
		help="update an existing graph, or extract fresh when no graph exists",
	)
	mode_group.add_argument(
		"-C", "--context",
		dest="mode",
		action="store_const",
		const=MODE_CONTEXT,
		help="print existing-map orientation, or help when no map exists",
	)
	mode_group.add_argument(
		"-R", "--reflect",
		dest="mode",
		action="store_const",
		const=MODE_REFLECT,
		help="aggregate saved query outcomes into the Graphify lessons file",
	)
	mode_group.add_argument(
		"-P", "--page",
		dest="mode",
		action="store_const",
		const=MODE_PAGE,
		help="write the browsable repository-map page under docs/",
	)
	parser.add_argument(
		"-S", "--force-shrink",
		dest="force_shrink",
		action="store_true",
		help="let an update write a smaller graph, after code was deleted",
	)
	parser.add_argument(
		"-M", "--deep",
		dest="deep_extraction",
		action="store_true",
		help="use aggressive inferred-edge semantic extraction",
	)
	parser.add_argument(
		"-G", "--global",
		dest="global_graph",
		action="store_true",
		help="also merge this repository into the shared cross-repository graph",
	)
	parser.add_argument(
		"-O", "--ollama",
		dest="label_backend",
		action="store_const",
		const=OLLAMA_BACKEND,
		help=f"use local Ollama model {OLLAMA_MODEL} for extraction and labels",
	)
	parser.add_argument(
		"-D", "--include-docs",
		dest="include_docs",
		action="store_true",
		help="include nonignored document, paper, and image inputs in fresh or update builds",
	)
	parser.set_defaults(
		mode=MODE_AUTO,
		label_backend=LABEL_BACKEND,
		include_docs=False,
		force_shrink=False,
		deep_extraction=False,
		global_graph=False,
	)
	return parser


#============================================


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
	"""Parse automatic or explicitly selected Graphify lifecycle modes."""
	parser = build_parser()
	args = parser.parse_args(argv)
	# ASVS 2.1.1 and 2.2.1: semantic extraction requires an explicit lifecycle mode.
	if args.include_docs and args.mode not in (MODE_FRESH, MODE_UPDATE):
		parser.error("--include-docs requires --fresh or --update")
	# Deep mode only affects the semantic extraction pass, not the code-only path.
	if args.deep_extraction and not args.include_docs:
		parser.error("--deep requires --include-docs")
	# Graphify's update subcommand has no global option, so a combination that
	# could never register the repository is rejected instead of silently ignored.
	if args.global_graph and args.mode not in (MODE_AUTO, MODE_FRESH):
		parser.error("--global requires a fresh extraction; use --fresh")
	if args.force_shrink and args.mode not in (MODE_AUTO, MODE_UPDATE):
		parser.error("--force-shrink applies only to an update")
	return args


#============================================


def get_repo_root() -> pathlib.Path:
	"""Return the Git repository root for the current working directory."""
	# ASVS 1.2.5: pass arguments directly without a shell interpreter.
	result = subprocess.run(
		["git", "rev-parse", "--show-toplevel"],
		check=True,
		capture_output=True,
		text=True,
	)
	repo_root = pathlib.Path(result.stdout.strip()).resolve()
	return repo_root


#============================================


def require_repo_root(repo_root: pathlib.Path) -> None:
	"""Require the tool to run from the active repository root."""
	current_dir = pathlib.Path.cwd().resolve()
	if current_dir != repo_root:
		raise RuntimeError(f"Run this tool from the repository root: {repo_root}")


#============================================


def require_command(command_name: str) -> str:
	"""Return the resolved executable path or raise a setup error."""
	executable = shutil.which(command_name)
	if executable is None:
		raise RuntimeError(
			f"Required command '{command_name}' is unavailable. "
			"Install the repository's declared development dependencies first."
		)
	return executable


#============================================


def print_step(label: str) -> None:
	"""Print one prominent runtime phase label."""
	print()
	print(f"============ {label} ============")


#============================================


def run_command(
	command: list[str],
	repo_root: pathlib.Path,
	environment: dict[str, str] | None = None,
) -> None:
	"""Run one trusted Graphify lifecycle command from the repository root."""
	# ASVS 1.2.5: subprocesses use an argv list and never invoke a shell.
	subprocess.run(command, cwd=repo_root, check=True, env=environment)


#============================================


def upgrade_graphify(repo_root: pathlib.Path) -> None:
	"""Upgrade the declared Graphify package for a fresh extraction."""
	print_step("UPDATING GRAPHIFY PYTHON PACKAGE")
	# ASVS 1.2.5: fixed package input is passed as argv to the active interpreter.
	run_command(
		[
			sys.executable,
			"-m",
			"pip",
			"install",
			"--upgrade",
			"--quiet",
			"--no-cache-dir",
			GRAPHIFY_PACKAGE,
		],
		repo_root,
	)


#============================================


def prepare_label_backend(repo_root: pathlib.Path, label_backend: str) -> None:
	"""Require the selected label backend and prepare its local model when needed."""
	# ASVS 2.2.1: select the required executable from the supported backend allowlist.
	if label_backend not in (LABEL_BACKEND, OLLAMA_BACKEND):
		raise ValueError(f"Unsupported Graphify label backend: {label_backend}")
	backend_executable = require_command(
		"ollama" if label_backend == OLLAMA_BACKEND else "claude"
	)
	if label_backend == OLLAMA_BACKEND:
		print_step(f"PULLING OLLAMA MODEL: {OLLAMA_MODEL}")
		run_command([backend_executable, "pull", OLLAMA_MODEL], repo_root)


#============================================


def repo_has_cargo(repo_root: pathlib.Path) -> bool:
	"""Return whether this repository is a Cargo workspace."""
	# ASVS 5.3.2: one fixed marker path beneath the repository root.
	has_cargo = (repo_root / "Cargo.toml").is_file()
	return has_cargo


#============================================


def prunes_rust_tests(repo_root: pathlib.Path, is_fresh: bool) -> bool:
	"""Return whether this build prunes Rust test symbols before clustering.

	Gated on the same repository evidence that already selects --cargo, so a
	repository with no Rust keeps the original pipeline exactly. Limited to
	fresh builds: re-clustering renumbers communities, and a fresh build is the
	one path that always relabels afterward, so stored labels cannot go stale.
	"""
	prunes = is_fresh and repo_has_cargo(repo_root)
	return prunes


#============================================


def graph_build_is_fresh(repo_root: pathlib.Path, mode: str) -> bool:
	"""Return whether one automatic, fresh, or update build extracts a fresh graph."""
	if mode not in (MODE_AUTO, MODE_FRESH, MODE_UPDATE):
		raise ValueError(f"Unsupported Graphify mode: {mode}")
	graph_path = (
		repo_root
		/ graphify_context_lib.OUTPUT_DIR_NAME
		/ graphify_context_lib.GRAPH_FILE_NAME
	)
	graph_exists = graph_path.is_file()
	is_fresh = mode == MODE_FRESH or not graph_exists
	return is_fresh


#============================================


def graph_build_command(
	graphify_executable: str,
	repo_root: pathlib.Path,
	mode: str,
	include_docs: bool,
	label_backend: str,
	deep_extraction: bool = False,
	global_graph: bool = False,
	force_shrink: bool = False,
) -> tuple[str, list[str], bool]:
	"""Return the graph operation and whether it performs a fresh extraction."""
	# ASVS 2.2.1: accept only the two fixed Graphify semantic backends.
	if label_backend not in (LABEL_BACKEND, OLLAMA_BACKEND):
		raise ValueError(f"Unsupported Graphify label backend: {label_backend}")
	is_fresh = graph_build_is_fresh(repo_root, mode)
	if is_fresh or include_docs:
		map_scope = "CODE AND SEMANTIC MAP" if include_docs else "CODE MAP"
		if is_fresh and mode == MODE_UPDATE:
			operation = f"NO EXISTING GRAPH; EXTRACTING FRESH GRAPHIFY {map_scope}"
		elif is_fresh:
			operation = f"EXTRACTING GRAPHIFY {map_scope}"
		else:
			operation = f"UPDATING GRAPHIFY {map_scope}"
		command = [graphify_executable, "extract", "."]
		if include_docs:
			extraction_model = (
				OLLAMA_MODEL if label_backend == OLLAMA_BACKEND else CLAUDE_LABEL_MODEL
			)
			command.extend(
				[
					f"--backend={label_backend}",
					f"--model={extraction_model}",
				]
			)
			if deep_extraction:
				command.append("--mode=deep")
			if is_fresh:
				command.append("--force")
		else:
			command.append("--code-only")
		if repo_has_cargo(repo_root):
			command.append("--cargo")
		# Clustering is deferred so it never sees the Rust test symbols that
		# the prune step is about to remove.
		if prunes_rust_tests(repo_root, is_fresh):
			command.append("--no-cluster")
		# Registration merges this map into the shared cross-repository graph and
		# is only available on the extract path.
		if global_graph and is_fresh:
			command.extend(["--global", f"--as={repo_root.name}"])
	else:
		operation = "UPDATING GRAPHIFY CODE MAP"
		command = [graphify_executable, "update", "."]
		# Graphify refuses to shrink a graph unless forced, so a refactor that
		# deleted code otherwise leaves the map silently stale.
		if force_shrink:
			command.append("--force")
	return operation, command, is_fresh


#============================================


def graph_build_environment(
	include_docs: bool,
	label_backend: str,
) -> dict[str, str] | None:
	"""Pin the Claude CLI extraction model while preserving the parent environment."""
	if not include_docs or label_backend != LABEL_BACKEND:
		return None
	# ASVS 1.2.5 and 2.2.1: the environment key and model value are fixed constants.
	environment = os.environ.copy()
	environment["GRAPHIFY_CLAUDE_CLI_MODEL"] = CLAUDE_LABEL_MODEL
	return environment


#============================================


def label_graph(
	graphify_executable: str,
	repo_root: pathlib.Path,
	label_backend: str,
	missing_only: bool = False,
) -> None:
	"""Refresh Graphify community labels with the selected backend.

	An incremental build names only the communities that lack a label. A full
	relabel would re-pay for an LLM call per community when a handful changed.
	"""
	# ASVS 2.2.1: accept only the two documented label backends.
	if label_backend not in (LABEL_BACKEND, OLLAMA_BACKEND):
		raise ValueError(f"Unsupported Graphify label backend: {label_backend}")
	label_model = (
		OLLAMA_MODEL if label_backend == OLLAMA_BACKEND else CLAUDE_LABEL_MODEL
	)
	# ASVS 1.2.5: fixed backend and model values remain isolated in the argv list.
	command = [
		graphify_executable,
		"label",
		".",
		f"--backend={label_backend}",
		f"--model={label_model}",
	]
	if missing_only:
		command.append("--missing-only")
	run_command(command, repo_root)


#============================================


def prune_rust_tests_then_cluster(
	graphify_executable: str,
	repo_root: pathlib.Path,
) -> None:
	"""Remove Rust test symbols from the graph, then cluster what remains.

	Extraction ran with --no-cluster, so this is the only clustering pass and it
	never sees the test symbols. Labeling stays with the caller's configured
	backend, so cluster-only is told not to name communities itself.
	"""
	print_step("PRUNING RUST TEST SYMBOLS")
	graph_path = (
		repo_root
		/ graphify_context_lib.OUTPUT_DIR_NAME
		/ graphify_context_lib.GRAPH_FILE_NAME
	)
	summary = graphify_prune_tests.prune_graph_file(graph_path, repo_root)
	# Never silent: a build that changes the graph reports what it removed.
	print(
		f"Removed {summary['removed_nodes']} test nodes "
		f"and {summary['removed_links']} links."
	)
	print_step("CLUSTERING PRUNED GRAPHIFY CODE MAP")
	run_command([graphify_executable, "cluster-only", ".", "--no-label"], repo_root)


#============================================


def report_graph_diagnostics(
	graphify_executable: str,
	repo_root: pathlib.Path,
) -> None:
	"""Report same-endpoint edge collapse without failing the build.

	Graphify documents no reliable threshold for this measure, and repeated
	endpoint pairs are legitimate in some codebases, so this stays advisory. A
	diagnostic that could abort the run would make the tool unusable on exactly
	the unusual repositories it is meant to describe.
	"""
	# ASVS 1.2.5: fixed argv, no shell, and failures are reported rather than raised.
	result = subprocess.run(
		[graphify_executable, "diagnose", "multigraph", "--json"],
		cwd=repo_root,
		capture_output=True,
		text=True,
		check=False,
	)
	if result.returncode != 0:
		print("Graph diagnostics unavailable; skipping edge-collapse report.")
		return
	summary = json.loads(result.stdout)
	collapsed_edges = summary.get(COLLAPSED_EDGE_FIELD, 0)
	if not isinstance(collapsed_edges, int) or collapsed_edges <= 0:
		print("No same-endpoint edge collapse detected.")
		return
	print(f"Same-endpoint edge collapse: {collapsed_edges} edges merged.")
	print("Distinct relationships between the same two symbols share one edge.")


#============================================


def reflect_on_saved_results(
	graphify_executable: str,
	repo_root: pathlib.Path,
) -> None:
	"""Aggregate saved query outcomes into the Graphify lessons file."""
	print_step("AGGREGATING GRAPHIFY QUERY OUTCOMES")
	run_command([graphify_executable, "reflect"], repo_root)
	found_lessons_path = graphify_context_lib.lessons_path(repo_root)
	if found_lessons_path is None:
		print("No saved query outcomes yet; record them with graphify save-result.")
		return
	print(f"Lessons written to {found_lessons_path.relative_to(repo_root)}")


#============================================


def validate_core_artifacts(repo_root: pathlib.Path) -> None:
	"""Require the graph needed for targeted Graphify traversal."""
	graph_path = (
		repo_root
		/ graphify_context_lib.OUTPUT_DIR_NAME
		/ graphify_context_lib.GRAPH_FILE_NAME
	)
	if not graph_path.is_file():
		raise RuntimeError(f"Required Graphify artifact is missing: {graph_path}")


#============================================


def print_context(repo_root: pathlib.Path) -> None:
	"""Print existing-map orientation or CLI help before the first build."""
	context = graphify_context_lib.manager_context(repo_root)
	if context is None:
		print(f"No Graphify map exists in {graphify_context_lib.OUTPUT_DIR_NAME}/ yet.")
		print("Run without a mode, with --fresh, or with --update to build the first map.")
		print()
		build_parser().print_help()
		return
	print(context)
	# Advisory only: orientation is the point of this mode, so a stale map still
	# prints in full and the warning is appended to it.
	if graphify_context_lib.graph_needs_update(repo_root):
		print("Map is stale: non-code changes are pending.")
		print("Refresh it with --update --include-docs.")


#============================================


def write_map_page(repo_root: pathlib.Path) -> None:
	"""Write the repository-map page from artifacts, without rebuilding the map."""
	if graphify_context_lib.manager_context(repo_root) is None:
		print(f"No Graphify map exists in {graphify_context_lib.OUTPUT_DIR_NAME}/ yet.")
		print("Run without a mode, with --fresh, or with --update to build the first map.")
		return
	print_step("WRITING GRAPHIFY REPOSITORY MAP PAGE")
	graphify_executable = require_command("graphify")
	page_path, figure_summary = graphify_docs_lib.write_page(graphify_executable, repo_root)
	if figure_summary is None:
		print("Figure skipped: graphify export svg was unavailable.")
	else:
		source_kb = figure_summary["source_bytes"] / 1024
		target_kb = figure_summary["target_bytes"] / 1024
		print(
			f"Figure cleaned: {source_kb:.0f} KB to {target_kb:.0f} KB, "
			f"{figure_summary['removed_labels']} node labels removed, "
			f"{figure_summary['kept_labels']} community labels kept."
		)
	print(f"Page written to {page_path.relative_to(repo_root)}")


#============================================


def main() -> None:
	"""Run the selected Graphify lifecycle or print artifact-driven orientation."""
	args = parse_args()
	repo_root = get_repo_root()
	require_repo_root(repo_root)
	if args.mode == MODE_CONTEXT:
		print_context(repo_root)
		return
	if args.mode == MODE_REFLECT:
		reflect_on_saved_results(require_command("graphify"), repo_root)
		return
	if args.mode == MODE_PAGE:
		write_map_page(repo_root)
		return

	is_fresh = graph_build_is_fresh(repo_root, args.mode)
	needs_labeling = is_fresh or args.include_docs
	if not needs_labeling and args.label_backend == OLLAMA_BACKEND:
		raise ValueError("--ollama applies only to fresh or --include-docs builds")
	if is_fresh:
		upgrade_graphify(repo_root)
	if needs_labeling:
		prepare_label_backend(repo_root, args.label_backend)
	graphify_executable = require_command("graphify")
	operation, build_command, is_fresh = graph_build_command(
		graphify_executable,
		repo_root,
		args.mode,
		args.include_docs,
		args.label_backend,
		args.deep_extraction,
		args.global_graph,
		args.force_shrink,
	)
	print_step(operation)
	build_environment = graph_build_environment(
		args.include_docs,
		args.label_backend,
	)
	run_command(build_command, repo_root, build_environment)
	if prunes_rust_tests(repo_root, is_fresh):
		prune_rust_tests_then_cluster(graphify_executable, repo_root)
	if needs_labeling:
		print_step("LABELING GRAPHIFY COMMUNITIES")
		label_graph(
			graphify_executable,
			repo_root,
			args.label_backend,
			missing_only=not is_fresh,
		)
	if is_fresh:
		map_scope = "CODE AND SEMANTIC MAP" if args.include_docs else "CODE MAP"
		print_step(f"BENCHMARKING GRAPHIFY {map_scope}")
		run_command([graphify_executable, "benchmark"], repo_root)
		print_step("CHECKING GRAPHIFY EDGE FIDELITY")
		report_graph_diagnostics(graphify_executable, repo_root)

	validate_core_artifacts(repo_root)
	context = graphify_context_lib.manager_context(repo_root)
	if context is None:
		raise RuntimeError("Graphify output did not contain usable manager context data")
	context_path = graphify_context_lib.write_manager_context(repo_root, context)

	print()
	print("======================================================================")
	print("GRAPHIFY READY")
	print("======================================================================")
	print()
	print(context)
	print()
	print(f"Manager context written to {context_path.relative_to(repo_root)}")


if __name__ == "__main__":
	main()
