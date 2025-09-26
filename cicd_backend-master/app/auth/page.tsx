"use client"

import { useState } from "react"
import Link from "next/link"
import { useSearchParams } from "next/navigation"
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { ChefHat } from "lucide-react"
import { AuthForm } from "@/components/auth-form"

export default function AuthPage() {
  const searchParams = useSearchParams()
  const defaultTab = searchParams.get("signup") ? "signup" : "login"
  const [activeTab, setActiveTab] = useState(defaultTab)

  return (
    <div className="flex flex-col min-h-screen bg-orange-50">
      <div className="container flex flex-col items-center justify-center flex-1 px-4 py-12 md:px-6">
        <Link href="/" className="flex items-center gap-2 mb-8">
          <ChefHat className="w-8 h-8 text-orange-500" />
          <span className="text-2xl font-bold">FoodPath</span>
        </Link>
        <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full max-w-md">
          <TabsList className="grid w-full grid-cols-2">
            <TabsTrigger value="login">Login</TabsTrigger>
            <TabsTrigger value="signup">Sign Up</TabsTrigger>
          </TabsList>
          <TabsContent value="login">
            <Card>
              <CardHeader>
                <CardTitle>Login to your account</CardTitle>
                <CardDescription>Enter your email and password to access your recipes</CardDescription>
              </CardHeader>
              <CardContent>
                <AuthForm type="login" />
              </CardContent>
              <CardFooter className="flex justify-center">
                <Link href="/auth/forgot-password" className="text-sm text-orange-500 hover:underline">
                  Forgot password?
                </Link>
              </CardFooter>
            </Card>
          </TabsContent>
          <TabsContent value="signup">
            <Card>
              <CardHeader>
                <CardTitle>Create an account</CardTitle>
                <CardDescription>Join our community of food enthusiasts</CardDescription>
              </CardHeader>
              <CardContent>
                <AuthForm type="signup" />
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
    </div>
  )
}
