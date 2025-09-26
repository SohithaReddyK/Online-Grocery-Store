"use client"

import { useState, useEffect } from "react"
import { Button } from "@/components/ui/button"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { testBackendConnection } from "@/utils/api"
import { CheckCircle, XCircle, RefreshCw, InfoIcon } from "lucide-react"

export function ConnectionTester() {
  const [connectionStatus, setConnectionStatus] = useState<{
    tested: boolean
    success: boolean
    message: string
    usingMock: boolean
  }>({
    tested: false,
    success: false,
    message: "",
    usingMock: false,
  })

  const [isLoading, setIsLoading] = useState(false)

  const testConnection = async () => {
    setIsLoading(true)
    try {
      const result = await testBackendConnection()
      setConnectionStatus({
        tested: true,
        success: result.success,
        message: result.message,
        usingMock: result.message.includes("mock") || result.message.includes("demonstration"),
      })
    } catch (error: any) {
      setConnectionStatus({
        tested: true,
        success: false,
        message: `Connection failed: ${error.message}`,
        usingMock: true,
      })
    } finally {
      setIsLoading(false)
    }
  }

  useEffect(() => {
    // Test connection when component mounts
    testConnection()
  }, [])

  return (
    <div className="space-y-4">
      {connectionStatus.tested && (
        <Alert variant={connectionStatus.usingMock ? "default" : connectionStatus.success ? "default" : "destructive"}>
          <div className="flex items-center gap-2">
            {connectionStatus.success && !connectionStatus.usingMock ? (
              <CheckCircle className="h-5 w-5 text-green-500" />
            ) : connectionStatus.usingMock ? (
              <InfoIcon className="h-5 w-5 text-blue-500" />
            ) : (
              <XCircle className="h-5 w-5" />
            )}
            <AlertTitle>
              {connectionStatus.success && !connectionStatus.usingMock
                ? "Connection Successful"
                : connectionStatus.usingMock
                  ? "Demo Mode Active"
                  : "Connection Failed"}
            </AlertTitle>
          </div>
          <AlertDescription>{connectionStatus.message}</AlertDescription>

          {connectionStatus.usingMock && (
            <div className="mt-2 text-sm">
              <p>The app is running in demo mode with mock data. You can still explore all features.</p>
              <p className="mt-1">To connect to a real backend:</p>
              <ol className="list-decimal ml-5 mt-1">
                <li>Ensure your backend server is running on port 9001</li>
                <li>Check for any CORS or network issues</li>
                <li>Click "Test Connection" to try again</li>
              </ol>
            </div>
          )}
        </Alert>
      )}

      <Button onClick={testConnection} disabled={isLoading} variant="outline" className="flex items-center gap-2">
        {isLoading ? <RefreshCw className="h-4 w-4 animate-spin" /> : <RefreshCw className="h-4 w-4" />}
        Test Connection
      </Button>
    </div>
  )
}
