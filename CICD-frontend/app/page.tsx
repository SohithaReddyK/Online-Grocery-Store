"use client"

import { useState } from "react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"

export default function HomePage() {
  const [currentView, setCurrentView] = useState<"welcome" | "signin" | "signup">("welcome")

  const WelcomeView = () => (
    <div className="min-h-screen relative flex items-center justify-center">
      {/* Background Image */}
      <div
        className="absolute inset-0 bg-cover bg-center bg-no-repeat"
        style={{
          backgroundImage: `url('/fresh-grocery-background-with-fruits-vegetables-br.jpg')`,
        }}
      >
        <div className="absolute inset-0 bg-black/40" />
      </div>

      {/* Content */}
      <div className="relative z-10 text-center text-white px-4">
        <h1 className="text-6xl font-bold mb-8 text-balance">Welcome to Online Grocery Store</h1>
        <p className="text-xl mb-12 text-balance max-w-2xl mx-auto">
          Fresh groceries delivered to your doorstep. Shop from our wide selection of fruits, vegetables, dairy, and
          more.
        </p>
        <div className="flex gap-4 justify-center">
          <Button size="lg" className="px-8 py-3 text-lg" onClick={() => setCurrentView("signin")}>
            Sign In
          </Button>
          <Button size="lg" variant="secondary" className="px-8 py-3 text-lg" onClick={() => setCurrentView("signup")}>
            Visit Dashboard
          </Button>
        </div>
      </div>
    </div>
  )

  const SignInView = () => (
    <div className="min-h-screen flex items-center justify-center bg-muted/30 px-4">
      <Card className="w-full max-w-md">
        <CardHeader className="text-center">
          <CardTitle className="text-2xl">Sign In</CardTitle>
          <CardDescription>Enter your credentials to access your account</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="username">Enter your Username</Label>
            <Input id="username" type="text" placeholder="Username" />
          </div>
          <div className="space-y-2">
            <Label htmlFor="password">Enter your Password</Label>
            <Input id="password" type="password" placeholder="Password" />
          </div>
          <Button className="w-full" onClick={() => (window.location.href = "/dashboard")}>
            Login
          </Button>
          <div className="text-center">
            <button className="text-sm text-primary hover:underline" onClick={() => setCurrentView("signup")}>
              Don't have an account? Sign Up
            </button>
          </div>
          <div className="text-center">
            <button className="text-sm text-muted-foreground hover:underline" onClick={() => setCurrentView("welcome")}>
              ← Back to Welcome
            </button>
          </div>
        </CardContent>
      </Card>
    </div>
  )

  const SignUpView = () => (
    <div className="min-h-screen flex items-center justify-center bg-muted/30 px-4">
      <Card className="w-full max-w-md">
        <CardHeader className="text-center">
          <CardTitle className="text-2xl">Sign Up</CardTitle>
          <CardDescription>Create your account to start shopping</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="name">Enter your Name</Label>
            <Input id="name" type="text" placeholder="Full Name" />
          </div>
          <div className="space-y-2">
            <Label htmlFor="email">Enter your Gmail account</Label>
            <Input id="email" type="email" placeholder="email@gmail.com" />
          </div>
          <div className="space-y-2">
            <Label htmlFor="signup-password">Enter your Password</Label>
            <Input id="signup-password" type="password" placeholder="Password" />
          </div>
          <div className="space-y-2">
            <Label htmlFor="confirm-password">Confirm your Password</Label>
            <Input id="confirm-password" type="password" placeholder="Confirm Password" />
          </div>
          <Button className="w-full" onClick={() => (window.location.href = "/dashboard")}>
            Sign Up
          </Button>
          <div className="text-center">
            <button className="text-sm text-primary hover:underline" onClick={() => setCurrentView("signin")}>
              Already have an account? Login
            </button>
          </div>
          <div className="text-center">
            <button className="text-sm text-muted-foreground hover:underline" onClick={() => setCurrentView("welcome")}>
              ← Back to Welcome
            </button>
          </div>
        </CardContent>
      </Card>
    </div>
  )

  return (
    <>
      {currentView === "welcome" && <WelcomeView />}
      {currentView === "signin" && <SignInView />}
      {currentView === "signup" && <SignUpView />}
    </>
  )
}
