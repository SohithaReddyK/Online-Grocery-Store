import Link from "next/link"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { ChefHat } from "lucide-react"

export default function ForgotPasswordPage() {
  return (
    <div className="flex flex-col min-h-screen bg-orange-50">
      <div className="container flex flex-col items-center justify-center flex-1 px-4 py-12 md:px-6">
        <Link href="/" className="flex items-center gap-2 mb-8">
          <ChefHat className="w-8 h-8 text-orange-500" />
          <span className="text-2xl font-bold">FoodPath</span>
        </Link>
        <Card className="w-full max-w-md">
          <CardHeader>
            <CardTitle>Reset your password</CardTitle>
            <CardDescription>Enter your email to receive a password reset link</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="email">Email</Label>
              <Input id="email" type="email" placeholder="your@email.com" />
            </div>
          </CardContent>
          <CardFooter className="flex flex-col gap-4">
            <Button className="w-full bg-orange-500 hover:bg-orange-600">Send Reset Link</Button>
            <Link href="/auth" className="text-sm text-center text-orange-500 hover:underline">
              Back to login
            </Link>
          </CardFooter>
        </Card>
      </div>
    </div>
  )
}
