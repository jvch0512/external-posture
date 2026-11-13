node dist/src/cli.js analyze examples/weak-fintech.json > /tmp/weak.md
diff /tmp/weak.md docs/sample-weak.md
node dist/src/cli.js analyze examples/weak-fintech.json --lang es > /tmp/weak.es.md
diff /tmp/weak.es.md docs/sample-weak.es.md
node dist/src/cli.js analyze examples/strong-fintech.json --fail-under 90 > /tmp/strong.md
diff /tmp/strong.md docs/sample-strong.md
test "$(node dist/src/cli.js analyze examples/weak-fintech.json --fail-under 90 >/dev/null; echo $?)" = "1"
