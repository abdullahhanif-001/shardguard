import Foundation;class R{func go(){let p=Process();p.executableURL=URL(fileURLWithPath:"/bin/sh");try?p.run()}}
