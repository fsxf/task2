import java.nio.charset.StandardCharsets
import java.nio.file.{Files, Paths}

@main def exec(inputPath: String, projectName: String, cwe: String, analysisScope: String, outFile: String) = {
  importCode(inputPath = inputPath, projectName = projectName)

  def sanitize(value: String): String =
    Option(value).getOrElse("").replace("\t", " ").replace("\r", " ").replace("\n", " ").trim

  def inScope(call: io.shiftleft.codepropertygraph.generated.nodes.Call): Boolean = {
    val scope = sanitize(analysisScope).toLowerCase
    if (scope.isEmpty) true
    else {
      val methodName = sanitize(call.method.name).toLowerCase
      val methodFullName = sanitize(call.method.fullName).toLowerCase
      methodName.contains(scope) || methodFullName.contains(scope)
    }
  }

  def formatCall(call: io.shiftleft.codepropertygraph.generated.nodes.Call): String = {
    val filename = sanitize(call.location.filename)
    val lineNumber = call.location.lineNumber.getOrElse(-1)
    val callName = sanitize(call.name)
    val methodName = sanitize(call.method.fullName)
    val code = sanitize(call.code)
    s"${filename}\t${lineNumber}\t${callName}\t${methodName}\t${code}"
  }

  val sourceRows =
    if (cwe == "CWE78")
      cpg.call.name("recv").filter(call => inScope(call)).map(call => s"SOURCE\t${formatCall(call)}").l
    else
      cpg.call.name("strcpy").filter(call => inScope(call) && sanitize(call.code).contains("PASSWORD")).map(call => s"SOURCE\t${formatCall(call)}").l

  val sinkRows =
    if (cwe == "CWE78")
      cpg.call.name("(EXECL|execl|_execl)").filter(call => inScope(call)).map(call => s"SINK\t${formatCall(call)}").l
    else
      cpg.call.name("LogonUserA").filter(call => inScope(call)).map(call => s"SINK\t${formatCall(call)}").l

  val rows = (sourceRows ++ sinkRows).mkString("\n")
  Files.write(Paths.get(outFile), rows.getBytes(StandardCharsets.UTF_8))
  close
}
