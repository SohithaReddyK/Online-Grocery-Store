import { ConnectionTester } from "@/components/connection-tester"
import Link from "next/link"
import { Button } from "@/components/ui/button"
import { ChefHat, ArrowLeft } from "lucide-react"

export default function TestConnectionPage() {
  return (
    <div className="flex flex-col min-h-screen bg-orange-50">
      <header className="bg-white border-b py-4">
        <div className="container mx-auto px-4 flex items-center justify-between">
          <Link href="/" className="flex items-center gap-2">
            <ChefHat className="w-6 h-6 text-orange-500" />
            <span className="text-xl font-bold">FoodPath</span>
          </Link>
        </div>
      </header>

      <main className="flex-1 container mx-auto px-4 py-8">
        <div className="max-w-md mx-auto bg-white p-6 rounded-lg shadow-md">
          <h1 className="text-2xl font-bold mb-6">Backend Connection Test</h1>

          <p className="mb-4 text-gray-600">
            This page tests the connection between your frontend (localhost:3000) and backend (localhost:9001).
          </p>

          <ConnectionTester />

          <div className="mt-8 pt-4 border-t">
            <Link href="/">
              <Button variant="outline" className="flex items-center gap-2">
                <ArrowLeft className="h-4 w-4" />
                Back to Home
              </Button>
            </Link>
          </div>
        </div>
      </main>

      <footer className="py-6 bg-orange-500 text-white">
        <div className="container mx-auto px-4 text-center">
          <p>© 2024 FoodPath. All rights reserved.</p>
        </div>
      </footer>
    </div>
  )
}
