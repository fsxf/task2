import java.nio.charset.StandardCharsets
import java.nio.file.{Files, Paths}
import java.util.Base64

@main def exec(inputPath: String, projectName: String, cwe: String, variant: String, analysisScope: String, outFile: String) = {
  importCode(inputPath = inputPath, projectName = projectName)

  def sanitize(value: String): String =
    Option(value).getOrElse("").replace("\t", " ").replace("\r", " ").replace("\n", " ").trim

  def encode(value: String): String =
    Base64.getEncoder.encodeToString(Option(value).getOrElse("").getBytes(StandardCharsets.UTF_8))

  def inScope(call: io.shiftleft.codepropertygraph.generated.nodes.Call): Boolean = {
    val scope = sanitize(analysisScope).toLowerCase
    if (scope.isEmpty) true
    else {
      val methodName = sanitize(call.method.name).toLowerCase
      val methodFullName = sanitize(call.method.fullName).toLowerCase
      methodName.contains(scope) || methodFullName.contains(scope)
    }
  }

  def methodInScope(method: io.shiftleft.codepropertygraph.generated.nodes.Method): Boolean = {
    val scope = sanitize(analysisScope).toLowerCase
    if (scope.isEmpty) true
    else {
      val methodName = sanitize(method.name).toLowerCase
      val methodFullName = sanitize(method.fullName).toLowerCase
      methodName.contains(scope) || methodFullName.contains(scope)
    }
  }

  def formatCall(kind: String, call: io.shiftleft.codepropertygraph.generated.nodes.Call): String = {
    val filename = sanitize(call.location.filename)
    val lineNumber = call.location.lineNumber.getOrElse(-1)
    val callName = sanitize(call.name)
    val methodName = sanitize(call.method.fullName)
    val code = sanitize(call.code)
    s"${kind}\t${filename}\t${lineNumber}\t${callName}\t${methodName}\t${code}"
  }

  def formatMethod(method: io.shiftleft.codepropertygraph.generated.nodes.Method): String = {
    val filename = sanitize(method.filename)
    val lineStart = method.lineNumber.getOrElse(-1)
    val lineEnd = method.lineNumberEnd.getOrElse(-1)
    val fullName = sanitize(method.fullName)
    val codeB64 = encode(method.code)
    s"METHOD\t${filename}\t${lineStart}\t${lineEnd}\t${fullName}\t${codeB64}"
  }

  val sourceRows =
    if (cwe == "CWE78")
      cpg.call.name("recv").filter(call => inScope(call)).map(call => formatCall("SOURCE", call)).l
    else
      cpg.call
        .name("(strcpy|__builtin___strcpy_chk)")
        .filter(call => inScope(call) && sanitize(call.code).toLowerCase.contains("password"))
        .map(call => formatCall("SOURCE", call))
        .l

  val sinkRows =
    if (cwe == "CWE78")
      cpg.call.name("(EXECL|execl|_execl)").filter(call => inScope(call)).map(call => formatCall("SINK", call)).l
    else
      cpg.call.name("LogonUserA").filter(call => inScope(call)).map(call => formatCall("SINK", call)).l

  val callEdgeRows =
    cpg.call
      .filter(call => inScope(call))
      .flatMap { call =>
        val caller = call.method
        val filename = sanitize(call.location.filename)
        val lineNumber = call.location.lineNumber.getOrElse(-1)
        val callerName = sanitize(caller.fullName)
        val code = sanitize(call.code)
        call.callee
          .filter(method => methodInScope(method))
          .map(callee => s"CALL_EDGE\t${filename}\t${lineNumber}\t${callerName}\t${sanitize(callee.fullName)}\t${code}")
      }
      .dedup
      .l

  val methodRows =
    cpg.method
      .filter(method => sanitize(method.fullName).nonEmpty)
      .map(method => formatMethod(method))
      .dedup
      .l

  val rows = (sourceRows ++ sinkRows ++ callEdgeRows ++ methodRows).mkString("\n")
  Files.write(Paths.get(outFile), rows.getBytes(StandardCharsets.UTF_8))
  close
}
