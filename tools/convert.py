#!/usr/bin/env python3
"""Convert every Sigma rule in frameworks/*/sigma/ and behaviors/sigma/ to Splunk SPL, Microsoft Sentinel / Defender KQL and Elastic ES|QL and Lucene.

    pip install -r tools/requirements.txt
    python3 tools/convert.py            # writes generated/<backend>/<framework or behaviors>/<rule>.txt and generated/SUMMARY.md

Each rule is tried against several pipelines per backend. The first pipeline that converts it wins.
A rule that no pipeline can map for a backend is listed in SUMMARY.md, so you know to use the
hand-written native query in sentinel/, splunk/ or elastic/ instead.

Generated queries use the field names of the chosen pipeline. Check them against your own data model.
"""
import os
import copy
import sys
from pathlib import Path

from sigma.collection import SigmaCollection
from sigma.correlations import SigmaCorrelationRule
from sigma.processing.pipeline import ProcessingPipeline

ROOT = Path(__file__).resolve().parent.parent
SIGMA_DIRS = sorted(ROOT.glob("frameworks/*/sigma")) + [ROOT / "behaviors" / "sigma"]


def rel_of(path):
    """frameworks/artex/sigma/web/x.yml -> artex/web/x.yml, behaviors/sigma/web/x.yml -> behaviors/web/x.yml"""
    for d in SIGMA_DIRS:
        if d in path.parents:
            return Path(d.parent.name) / path.relative_to(d)
    raise ValueError(path)
OUT = ROOT / "generated"


def write(path, text):
    # UTF-8 whatever the locale: pySigma's windash expansion writes U+2013 to U+2015
    path.write_text(text, encoding="utf-8")


def ecs():
    from sigma.pipelines.elasticsearch.windows import ecs_windows
    # ecs_windows only maps Windows rules. Linux and product-less process rules get the same ECS process fields.
    from sigma.processing.conditions import LogsourceCondition
    from sigma.processing.pipeline import ProcessingItem
    from sigma.processing.transformations import FieldMappingTransformation
    process_fields = {"CommandLine": "process.command_line", "Image": "process.executable", "ParentImage": "process.parent.executable",
                      "ParentCommandLine": "process.parent.command_line", "User": "user.name", "CurrentDirectory": "process.working_directory"}
    network_fields = {
        "dns_query": {"QueryName": "dns.question.name"},
        "proxy": {"c-uri": "url.original", "c-useragent": "user_agent.original", "cs-host": "url.domain"},
        "webserver": {"cs-uri-stem": "url.path", "cs-uri-query": "url.query", "cs-user-agent": "user_agent.original", "cs-host": "url.domain"},
    }
    network_pipeline = ProcessingPipeline(name="ECS DNS, proxy and web server fields", priority=30, items=[
        ProcessingItem(identifier=f"ecs_{category}_fields", transformation=FieldMappingTransformation(fields),
                       rule_conditions=[LogsourceCondition(category=category)])
        for category, fields in network_fields.items()])
    # Cloud logs: the field names of Elastic's AWS and Azure integrations (logs-aws.cloudtrail-*, logs-azure.*-*).
    cloud_fields = {
        ("aws", "cloudtrail"): {"eventName": "event.action", "eventSource": "event.provider", "errorCode": "aws.cloudtrail.error_code",
                                "errorMessage": "aws.cloudtrail.error_message", "userIdentity.arn": "aws.cloudtrail.user_identity.arn",
                                "userAgent": "user_agent.original", "sourceIPAddress": "source.address",
                                # The integration keeps request parameters as one string, so a contains match still works.
                                "requestParameters.filterPattern": "aws.cloudtrail.request_parameters",
                                "requestParameters.userAttributes": "aws.cloudtrail.request_parameters"},
        ("azure", "signinlogs"): {"ResultType": "azure.signinlogs.properties.status.error_code",
                                  "UserPrincipalName": "azure.signinlogs.properties.user_principal_name",
                                  "IPAddress": "source.ip", "userAgent": "user_agent.original"},
        ("azure", "activitylogs"): {"operationName": "azure.activitylogs.operation_name",
                                    "caller": "azure.activitylogs.identity.claims_initiated_by_user.name"},
        ("azure", "auditlogs"): {"properties.message": "azure.auditlogs.operation_name"},
    }
    cloud_pipeline = ProcessingPipeline(name="ECS fields of the AWS and Azure integrations", priority=30, items=[
        ProcessingItem(identifier=f"ecs_{product}_{service}_fields", transformation=FieldMappingTransformation(fields),
                       rule_conditions=[LogsourceCondition(product=product, service=service)])
        for (product, service), fields in cloud_fields.items()] + [
        # ecs_windows leaves Computer as a winlog field; ECS and Elastic Defend carry the host in host.name.
        ProcessingItem(identifier="ecs_windows_host", transformation=FieldMappingTransformation({"winlog.event_data.Computer": "host.name"}),
                       rule_conditions=[LogsourceCondition(product="windows")])])
    # Elasticsearch regexes and keyword fields differ from Sigma's: see elastic_values.py.
    from sigma.processing.conditions import IncludeFieldCondition
    from elastic_values import HOST_FIELDS, CaseFoldTransformation, LuceneRegexTransformation
    values_pipeline = ProcessingPipeline(name="Sigma regexes and host name case in Elasticsearch", priority=40, items=[
        ProcessingItem(identifier="ecs_lucene_regex", transformation=LuceneRegexTransformation()),
        ProcessingItem(identifier="ecs_host_case", transformation=CaseFoldTransformation(),
                       field_name_conditions=[IncludeFieldCondition(fields=HOST_FIELDS)])])
    return ecs_windows() + ProcessingPipeline(name="ECS process fields for non-Windows rules", priority=30, items=[
        ProcessingItem(identifier="ecs_process_fields", transformation=FieldMappingTransformation(process_fields),
                       rule_conditions=[LogsourceCondition(category="process_creation")])]) + network_pipeline + cloud_pipeline + values_pipeline


def pipelines():
    """Return {backend_name: (backend_class, [(pipeline_label, pipeline_or_None), ...])}."""
    from sigma.backends.splunk import SplunkBackend
    from sigma.backends.kusto import KustoBackend
    from sigma.backends.elasticsearch import LuceneBackend, ESQLBackend
    from sigma.pipelines.microsoftxdr import microsoft_xdr_pipeline
    from sigma.pipelines.sentinelasim import sentinel_asim_pipeline
    from sigma.pipelines.azuremonitor import azure_monitor_pipeline
    from sigma.pipelines.splunk import splunk_windows_pipeline

    return {
        "splunk": (SplunkBackend, [("splunk_windows", splunk_windows_pipeline()), ("raw fields", None)]),
        "sentinel_asim": (KustoBackend, [("sentinel_asim", sentinel_asim_pipeline())]),
        "defender_xdr": (KustoBackend, [("microsoft_xdr", microsoft_xdr_pipeline())]),
        "azure_monitor": (KustoBackend, [("azure_monitor", azure_monitor_pipeline())]),
        "elastic_esql": (ESQLBackend, [("ecs", ecs()), ("raw fields", None)]),
        "elastic_lucene": (LuceneBackend, [("ecs", ecs()), ("raw fields", None)]),
    }


def convert_one(backend_cls, pipeline, collection):
    backend = backend_cls(processing_pipeline=pipeline) if pipeline is not None else backend_cls()
    return backend.convert(collection)


def main():
    files = sorted(p for d in SIGMA_DIRS for p in d.rglob("*.yml"))
    base = SigmaCollection.load_ruleset([str(p) for p in files])
    results = {}
    targets = pipelines()
    for rule in base.rules:
        path = Path(str(rule.source.path)) if rule.source else None
        if isinstance(rule, SigmaCorrelationRule):
            coll = SigmaCollection([r.rule for r in rule.rules] + [rule])
        else:
            coll = SigmaCollection([rule])
        rel = rel_of(path)
        for name, (cls, plist) in targets.items():
            done = None
            for label, pipe in plist:
                try:
                    # A pipeline rewrites field names on the rule objects it is given, so every backend gets its own copy.
                    out = convert_one(cls, pipe, copy.deepcopy(coll))
                    if out:
                        done = (label, out[-1] if isinstance(rule, SigmaCorrelationRule) else "\n".join(map(str, out)))
                        break
                except Exception as exc:  # noqa: BLE001 - report and try the next pipeline
                    last = f"{type(exc).__name__}: {exc}"
            if done:
                dest = OUT / name / rel.with_suffix(".txt")
                dest.parent.mkdir(parents=True, exist_ok=True)
                write(dest, f"# {rule.title}\n# Sigma id {rule.id}, pipeline {done[0]}\n{done[1]}\n")
                results.setdefault(rel.as_posix(), {})[name] = done[0]
            else:
                results.setdefault(rel.as_posix(), {})[name] = "-"
    names = list(targets)
    lines = ["# Conversion summary", "", "Generated by `tools/convert.py`. A dash means no pipeline mapped the rule for that backend: use the hand-written query instead.", "",
             "| Rule | " + " | ".join(names) + " |", "|---|" + "---|" * len(names)]
    for rel in sorted(results):
        lines.append(f"| `{rel}` | " + " | ".join(results[rel].get(n, "-") for n in names) + " |")
    OUT.mkdir(exist_ok=True)
    write(OUT / "SUMMARY.md", "\n".join(lines) + "\n")
    ok = sum(1 for r in results.values() for v in r.values() if v != "-")
    print(f"{len(results)} rules, {ok} conversions written to {OUT}")


if __name__ == "__main__":
    sys.exit(main())
