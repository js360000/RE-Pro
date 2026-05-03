import fs from "node:fs";
import parser from "@babel/parser";
import generate from "@babel/generator";
import traverseModule from "@babel/traverse";

const traverse = traverseModule.default || traverseModule;

function readStdin() {
  return new Promise((resolve, reject) => {
    let data = "";
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", chunk => {
      data += chunk;
    });
    process.stdin.on("end", () => resolve(data));
    process.stdin.on("error", reject);
  });
}

function parse(code, filename) {
  return parser.parse(code, {
    sourceType: "module",
    sourceFilename: filename,
    errorRecovery: true,
    plugins: [
      "jsx",
      "typescript",
      "classProperties",
      "classPrivateProperties",
      "classPrivateMethods",
      "dynamicImport",
      "importAttributes",
      "objectRestSpread",
      "optionalChaining",
      "nullishCoalescingOperator",
      "topLevelAwait",
    ],
  });
}

function summarize(ast) {
  const imports = [];
  const exports = [];
  const functions = [];
  const jsxElements = [];
  traverse(ast, {
    ImportDeclaration(path) {
      imports.push(String(path.node.source.value || ""));
    },
    ExportNamedDeclaration(path) {
      for (const specifier of path.node.specifiers || []) {
        exports.push(specifier.exported?.name || specifier.exported?.value || "");
      }
      if (path.node.declaration?.id?.name) {
        exports.push(path.node.declaration.id.name);
      }
    },
    ExportDefaultDeclaration() {
      exports.push("default");
    },
    FunctionDeclaration(path) {
      if (path.node.id?.name) {
        functions.push(path.node.id.name);
      }
    },
    JSXOpeningElement(path) {
      const name = path.node.name;
      if (name?.name) {
        jsxElements.push(name.name);
      }
    },
  });
  return {
    imports: [...new Set(imports.filter(Boolean))],
    exports: [...new Set(exports.filter(Boolean))],
    functions: [...new Set(functions)],
    jsx_elements: [...new Set(jsxElements)],
  };
}

try {
  const input = JSON.parse(await readStdin());
  const code = String(input.code || "");
  const filename = String(input.filename || "recovered.js");
  const ast = parse(code, filename);
  const generated = generate.default
    ? generate.default(ast, { comments: true, retainLines: false, jsescOption: { minimal: true } }, code)
    : generate(ast, { comments: true, retainLines: false, jsescOption: { minimal: true } }, code);
  const result = {
    ok: true,
    formatted: generated.code.endsWith("\n") ? generated.code : generated.code + "\n",
    summary: summarize(ast),
    errors: (ast.errors || []).map(error => String(error.message || error)),
  };
  process.stdout.write(JSON.stringify(result));
} catch (error) {
  process.stdout.write(JSON.stringify({ ok: false, error: String(error?.message || error) }));
  process.exitCode = 0;
}
