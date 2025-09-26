"use client"

import type React from "react"
import { useState } from "react"
import { useRouter } from "next/navigation"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { useToast } from "@/components/ui/use-toast"
import { authApi } from "@/utils/api"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { InfoIcon, AlertTriangle } from "lucide-react"

interface AuthFormProps {
  type: "login" | "signup"
}

export function AuthForm({ type }: AuthFormProps) {
  const router = useRouter()
  const { toast } = useToast()

  const [formData, setFormData] = useState({
    name: "",
    email: "",
    password: "",
    confirmPassword: "",
  })

  const [isLoading, setIsLoading] = useState(false)
  const [backendStatus, setBackendStatus] = useState<{
    checked: boolean
    available: boolean
    serverError: boolean
    errorDetails?: any
  }>({
    checked: false,
    available: true,
    serverError: false,
  })

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target
    setFormData((prev) => ({ ...prev, [name]: value }))
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setIsLoading(true)

    try {
      let result

      if (type === "login") {
        result = await authApi.login({
          email: formData.email,
          password: formData.password,
        })
      } else {
        // Check if passwords match for signup
        if (formData.password !== formData.confirmPassword) {
          toast({
            title: "Error",
            description: "Passwords do not match",
            variant: "destructive",
          })
          setIsLoading(false)
          return
        }

        result = await authApi.register(formData)
      }

      // Check if we got a server error
      if (result._wasServerError) {
        setBackendStatus({
          checked: true,
          available: true,
          serverError: true,
          errorDetails: result._errorDetails,
        })

        toast({
          title: "Server Error",
          description: "The server encountered an error. Using demo mode instead.",
          variant: "destructive",
        })
      }
      // Check if we got a mock response
      else if (result.message && result.message.includes("Mock")) {
        setBackendStatus({
          checked: true,
          available: false,
          serverError: false,
        })

        toast({
          title: "Demo Mode",
          description: "Using demo mode as backend is not available. You can still explore the app.",
          variant: "default",
        })
      } else {
        toast({
          title: type === "login" ? "Login successful" : "Account created",
          description: result.message || "Operation completed successfully",
        })
      }

      // Redirect to recipes page after successful auth
      router.push("/recipes")
    } catch (error: any) {
      toast({
        title: "Error",
        description: error.message || "An unexpected error occurred",
        variant: "destructive",
      })
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      {backendStatus.checked && !backendStatus.available && (
        <Alert>
          <InfoIcon className="h-4 w-4" />
          <AlertTitle>Demo Mode Active</AlertTitle>
          <AlertDescription>Backend server is not available. Using demo mode with mock data.</AlertDescription>
        </Alert>
      )}

      {backendStatus.serverError && (
        <Alert variant="destructive">
          <AlertTriangle className="h-4 w-4" />
          <AlertTitle>Server Error</AlertTitle>
          <AlertDescription>
            The server encountered an internal error (500). Using demo mode instead.
            <div className="mt-2 text-xs">
              <p>Error path: {backendStatus.errorDetails?.path || "/api/auth/signup"}</p>
              <p>Timestamp: {backendStatus.errorDetails?.timestamp || "N/A"}</p>
            </div>
          </AlertDescription>
        </Alert>
      )}

      {type === "signup" && (
        <div className="space-y-2">
          <Label htmlFor="name">Name</Label>
          <Input id="name" name="name" value={formData.name} onChange={handleChange} placeholder="Your name" required />
        </div>
      )}

      <div className="space-y-2">
        <Label htmlFor="email">Email</Label>
        <Input
          id="email"
          name="email"
          type="email"
          value={formData.email}
          onChange={handleChange}
          placeholder="your@email.com"
          required
        />
      </div>

      <div className="space-y-2">
        <Label htmlFor="password">Password</Label>
        <Input
          id="password"
          name="password"
          type="password"
          value={formData.password}
          onChange={handleChange}
          required
        />
      </div>

      {type === "signup" && (
        <div className="space-y-2">
          <Label htmlFor="confirmPassword">Confirm Password</Label>
          <Input
            id="confirmPassword"
            name="confirmPassword"
            type="password"
            value={formData.confirmPassword}
            onChange={handleChange}
            required
          />
        </div>
      )}

      <Button type="submit" className="w-full bg-orange-500 hover:bg-orange-600" disabled={isLoading}>
        {isLoading ? "Processing..." : type === "login" ? "Login" : "Sign Up"}
      </Button>
    </form>
  )
}
