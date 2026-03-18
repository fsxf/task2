import java.nio.charset.StandardCharsets
import java.nio.file.{Files, Paths}
import scala.util.Try

import io.joern.dataflowengineoss.language.*

@main def exec(inputPath: String, projectName: String, cwe: String, variant: String, analysisScope: String, outFile: String) = {
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

  def methodInScope(method: io.shiftleft.codepropertygraph.generated.nodes.Method): Boolean = {
    val scope = sanitize(analysisScope).toLowerCase
    if (scope.isEmpty) true
    else {
      val methodName = sanitize(method.name).toLowerCase
      val methodFullName = sanitize(method.fullName).toLowerCase
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

  def propertyString(node: io.shiftleft.codepropertygraph.generated.nodes.StoredNode, key: String): String =
    sanitize(Try(node.property(key).toString).getOrElse(""))

  def renderFlowNode(node: Any): String = node match {
    case stored: io.shiftleft.codepropertygraph.generated.nodes.StoredNode =>
      val label = sanitize(stored.label)
      val line = propertyString(stored, "LINE_NUMBER")
      val code = propertyString(stored, "CODE")
      val pieces = List(
        if (label.nonEmpty) Some(label) else None,
        if (line.nonEmpty) Some(s"line ${line}") else None,
        if (code.nonEmpty) Some(code) else None
      ).flatten
      pieces.mkString(" | ")
    case other => sanitize(other.toString)
  }

  def renderFlow(flow: io.joern.dataflowengineoss.language.Path): String =
    flow.elements.map(renderFlowNode).mkString(" -> ")

  def bestFlows(flows: List[io.joern.dataflowengineoss.language.Path], limit: Int = 1): List[io.joern.dataflowengineoss.language.Path] = {
    val ranked = flows.sortBy(flow => -flow.elements.size)
    ranked.foldLeft(List.empty[io.joern.dataflowengineoss.language.Path]) { (acc, flow) =>
      if (acc.size >= limit) acc
      else {
        val rendered = renderFlow(flow)
        if (acc.exists(existing => renderFlow(existing) == rendered)) acc
        else acc :+ flow
      }
    }
  }

  def formatDataflow(label: String, flows: List[io.joern.dataflowengineoss.language.Path]): List[String] =
    bestFlows(flows).map(flow => s"DATAFLOW\t.\t0\t${sanitize(label)}\t${sanitize(label)}\t${renderFlow(flow)}")

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

  val dataflowRows =
    if (cwe == "CWE259") {
      val flows =
        cpg.call
          .name("LogonUserA")
          .filter(call => inScope(call))
          .argument(3)
          .reachableByFlows(
            cpg.call
              .name("strcpy")
              .filter(call => inScope(call) && sanitize(call.code).contains("PASSWORD"))
              .argument(1)
          )
          .l
      formatDataflow("cwe259-password-to-logonuser", flows)
    } else if (Set("51", "52", "53", "54").contains(variant)) {
      val flows =
        cpg.method
          .name(".*badSink")
          .filter(method => methodInScope(method))
          .parameter
          .name("data")
          .reachableByFlows(
            cpg.call
              .name(".*badSink")
              .filter(call => inScope(call))
              .argument(1)
          )
          .l
      formatDataflow("cwe78-badsink-arg-to-param", flows)
    } else if (Set("81", "82").contains(variant)) {
      val flows =
        cpg.method
          .name("action")
          .filter(method => methodInScope(method))
          .parameter
          .name("data")
          .reachableByFlows(
            cpg.call
              .name("action")
              .filter(call => inScope(call))
              .argument(1)
          )
          .l
      formatDataflow("cwe78-action-arg-to-param", flows)
    } else {
      List.empty[String]
    }

  val rows = (sourceRows ++ sinkRows ++ callEdgeRows ++ dataflowRows).mkString("\n")
  Files.write(Paths.get(outFile), rows.getBytes(StandardCharsets.UTF_8))
  close
}
