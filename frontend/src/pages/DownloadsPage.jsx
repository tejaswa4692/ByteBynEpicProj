import { Terminal, Code2, DownloadCloud, CheckCircle2 } from 'lucide-react'
import NavBar from '@/components/NavBar'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Button } from '@/components/ui/button'

const pySnippet = `import requests
import sys

# RepodoGG CI/CD Security Check
API_URL = "https://YOUR_BACKEND_URL/scan"
REPO_URL = "YOUR_GITHUB_REPO_URL"

def check_vulnerabilities():
    try:
        res = requests.post(
            API_URL, 
            json={"repo_url": REPO_URL},
            headers={"Authorization": f"Bearer {os.getenv('REPODOGG_TOKEN')}"}
        )
        data = res.json()
        vulns = data.get('results', [])
        
        critical = sum(1 for v in vulns if v.get('severity') == 'CRITICAL')
        if critical > 0:
            print(f"FAILED Security Analysis: {critical} CRITICAL vulnerabilities found!")
            sys.exit(1)
            
        print("✅ Security Check Passed!")
    except Exception as e:
        print("Scanner Error:", e)

if __name__ == "__main__":
    check_vulnerabilities()
`

export default function DownloadsPage() {
  return (
    <div className="min-h-screen bg-background">
      <NavBar />
      <main className="max-w-4xl mx-auto px-6 py-12">
        <div className="text-center mb-12">
          <h1 className="text-3xl font-bold tracking-tight mb-3">Tools & Integrations</h1>
          <p className="text-muted-foreground">
            Integrate RepodoGG directly into your workflows. Use our standalone Windows tools or build custom Python CI/CD hooks.
          </p>
        </div>

        <div className="grid md:grid-cols-2 gap-8">
          {/* CLI Tool */}
          <Card className="flex flex-col border-primary/20 bg-primary/5">
            <CardHeader>
              <div className="w-12 h-12 flex items-center justify-center rounded-xl bg-blue-500/10 mb-4 border border-blue-500/20">
                <Terminal className="w-6 h-6 text-blue-500" />
              </div>
              <CardTitle>Windows CLI Scanner</CardTitle>
              <CardDescription>
                A standalone native Windows executable to trigger codebase analysis directly from your local terminal.
              </CardDescription>
            </CardHeader>
            <CardContent className="flex-1 flex flex-col justify-between">
              <ul className="space-y-2 mb-6">
                <li className="flex items-center gap-2 text-sm text-muted-foreground">
                  <CheckCircle2 className="w-4 h-4 text-green-400" /> Fast local indexing
                </li>
                <li className="flex items-center gap-2 text-sm text-muted-foreground">
                  <CheckCircle2 className="w-4 h-4 text-green-400" /> Deep AST node resolution
                </li>
                <li className="flex items-center gap-2 text-sm text-muted-foreground">
                  <CheckCircle2 className="w-4 h-4 text-green-400" /> Secure offline metadata
                </li>
              </ul>
              <a href="https://github.com/tejaswa4692/RepoDog/releases/tag/exe_release" target="_blank" rel="noreferrer" className="w-full">
                <Button className="w-full gap-2">
                  <DownloadCloud className="w-4 h-4" />
                  Download for Windows (x64)
                </Button>
              </a>
            </CardContent>
          </Card>

          {/* Python CI/CD */}
          <Card className="flex flex-col border-primary/20 bg-primary/5">
            <CardHeader>
              <div className="w-12 h-12 flex items-center justify-center rounded-xl bg-yellow-500/10 mb-4 border border-yellow-500/20">
                <Code2 className="w-6 h-6 text-yellow-500" />
              </div>
              <CardTitle>Python DevSecOps Script</CardTitle>
              <CardDescription>
                Use this Python snippet inside your CI/CD pipelines (e.g., GitHub Actions, Jenkins) to dynamically fail builds when critical vulnerabilities are introduced.
              </CardDescription>
            </CardHeader>
            <CardContent className="flex-1">
              <div className="relative group">
                
                <Button 
                  variant="outline" 
                  size="sm" 
                  className="absolute top-2 right-2 opacity-0 group-hover:opacity-100 transition-opacity bg-background/80 backdrop-blur"
                  onClick={() => navigator.clipboard.writeText(pySnippet)}
                >
                  Copy
                </Button>
              </div>
              <a href="https://github.com/tejaswa4692/RepoDog" target="_blank" rel="noreferrer" className="block mt-4">
                <Button variant="outline" className="w-full gap-2">
                  <Code2 className="w-4 h-4" /> View Full Script on GitHub
                </Button>
              </a>
            </CardContent>
          </Card>
        </div>
      </main>
    </div>
  )
}
