import scala.collection.mutable.Queue
import io.shiftleft.codepropertygraph.generated.nodes.Method
import scala.io.Source
import java.io.File
import java.nio.file.Paths

@main def main(): Unit = {
  // === 配置区 ===
  val cpgPath = "cpg.bin"        // 生成的图谱文件名
  val projName = "my_cwe_project"
  val sourceDir = "cleaned_code" // Python 脚本清洗后的输出目录

  println(s"[*] Loading graph database: $cpgPath ...")
  importCpg(inputPath = cpgPath, projectName = projName)

  // === 智能检测项目类型 ===
  val isCPP = cpg.file.name.exists(_.endsWith(".cpp"))

  if (isCPP) {
    println("[*] Detected C++ Object-Oriented Project. Switching to OOP Feature Slicing...")
    extractOOP(sourceDir)
  } else {
    println("[*] Detected C Procedural Project. Switching to Call Graph BFS...")
    extractProcedural(sourceDir)
  }
}

// 通用的物理文件代码读取逻辑
def printPhysicalCode(m: Method, sourceDir: String): Unit = {
  val rawFileName = new File(m.filename).getName 
  val actualFilePath = Paths.get(sourceDir, rawFileName).toString
  val startLine = m.lineNumber.getOrElse(-1)
  val endLine = m.lineNumberEnd.getOrElse(-1)
  val targetFile = new File(actualFilePath)
  
  if (startLine != -1 && endLine != -1 && targetFile.exists()) {
    try {
      val lines = Source.fromFile(targetFile, "UTF-8").getLines().toArray
      val fullCode = lines.slice(startLine - 1, endLine).mkString("\n")
      println(fullCode)
    } catch {
      case e: Exception => 
        println(s"// [Warning: Failed to read $actualFilePath. Using CPG code]")
        println(m.code) 
    }
  } else {
     println(s"// [Warning: File not found at '$actualFilePath'. Using CPG code]")
     println(m.code) 
  }
}

// 策略 1: 针对 C 语言的 BFS 调用图寻路
def extractProcedural(sourceDir: String): Unit = {
  val srcMethods = cpg.call("recv").method.l
  val snkMethods = cpg.call.name("execl", "_execl").method.l

  if (srcMethods.isEmpty || snkMethods.isEmpty) {
    println("[-] Error: Source or Sink not found in Call Graph.")
    return
  }

  val src = srcMethods.head
  val snk = snkMethods.head
  val queue = Queue(Seq(src))
  var visited = Set(src.fullName)
  var foundPath: Seq[Method] = Seq()

  while (queue.nonEmpty && foundPath.isEmpty) {
    val currentPath = queue.dequeue()
    val currentMethod = currentPath.last

    if (currentMethod.fullName == snk.fullName) {
      foundPath = currentPath
    } else {
      for (callee <- currentMethod.call.callee.l) {
        if (!visited.contains(callee.fullName) && !callee.isExternal) {
          visited += callee.fullName
          queue.enqueue(currentPath :+ callee)
        }
      }
    }
  }

  if (foundPath.nonEmpty) {
    println("==================================================")
    println("              FULL VULNERABILITY CALL CHAIN       ")
    println("==================================================")
    foundPath.zipWithIndex.foreach { case (m, idx) =>
      println(s"\n[Step ${idx + 1}] Method: ${m.name}")
      println("--------------------------------------------------")
      printPhysicalCode(m, sourceDir)
    }
  } else {
    println("[-] BFS Search Failed: No path found.")
  }
}

// 策略 2: 针对 C++ 的 OOP 虚函数切片打包
def extractOOP(sourceDir: String): Unit = {
  val sources = cpg.call("recv").method.l
  val sinks = cpg.call.name("execl", "_execl").method.l
  // 查找被子类具体实现的虚函数（此处以 action 为例）
  val virtualImpls = cpg.method.name("action").whereNot(_.isExternal).l

  println("==================================================")
  println("              OOP FEATURE SLICING CONTEXT         ")
  println("==================================================")

  println("\n[1. SOURCE (Data Entry Point)]")
  sources.distinct.foreach { m =>
    println(s"--- Method: ${m.name} ---")
    printPhysicalCode(m, sourceDir)
  }

  println("\n[2. VIRTUAL IMPLEMENTATIONS (Dynamic Dispatch Targets)]")
  virtualImpls.distinct.foreach { m =>
    println(s"--- Method: ${m.name} ---")
    printPhysicalCode(m, sourceDir)
  }

  println("\n[3. SINK (Execution Point)]")
  sinks.distinct.foreach { m =>
    println(s"--- Method: ${m.name} ---")
    printPhysicalCode(m, sourceDir)
  }
}