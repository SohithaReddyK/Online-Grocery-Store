"use client"

import { useState } from "react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Textarea } from "@/components/ui/textarea"
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card"

export default function ProfilePage() {
  const [username, setUsername] = useState("John Doe")
  const [savedAddresses, setSavedAddresses] = useState([
    "123 Main Street, City, Country",
    "456 Second Ave, City, Country",
  ])
  const [newAddress, setNewAddress] = useState("")
  const [currentPassword, setCurrentPassword] = useState("")
  const [newPassword, setNewPassword] = useState("")
  const [confirmPassword, setConfirmPassword] = useState("")

  const addAddress = () => {
    if (newAddress.trim() !== "") {
      setSavedAddresses([...savedAddresses, newAddress.trim()])
      setNewAddress("")
    }
  }

  const changePassword = () => {
    if (newPassword !== confirmPassword) {
      alert("New password and confirm password do not match!")
      return
    }
    if (!currentPassword || !newPassword) {
      alert("Please fill all password fields")
      return
    }
    // Add actual password change logic here
    alert("Password changed successfully!")
    setCurrentPassword("")
    setNewPassword("")
    setConfirmPassword("")
  }

  return (
    <div className="min-h-screen bg-background px-8 py-12 space-y-8">
      <h1 className="text-3xl font-bold mb-4">My Profile</h1>

      {/* Username */}
      <Card>
        <CardHeader>
          <CardTitle>Username</CardTitle>
          <CardDescription>Update your display name</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <Input
            type="text"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            placeholder="Enter your username"
          />
          <Button onClick={() => alert("Username updated!")}>Update Username</Button>
        </CardContent>
      </Card>

      {/* Saved Addresses */}
      <Card>
        <CardHeader>
          <CardTitle>Saved Addresses</CardTitle>
          <CardDescription>Your current saved delivery addresses</CardDescription>
        </CardHeader>
        <CardContent className="space-y-2">
          {savedAddresses.length === 0 ? (
            <p className="text-muted-foreground">No saved addresses yet.</p>
          ) : (
            savedAddresses.map((addr, index) => (
              <div key={index} className="flex justify-between items-center border rounded p-2">
                <span>{addr}</span>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() =>
                    setSavedAddresses(savedAddresses.filter((_, i) => i !== index))
                  }
                >
                  Remove
                </Button>
              </div>
            ))
          )}
        </CardContent>
      </Card>

      {/* Add New Address */}
      <Card>
        <CardHeader>
          <CardTitle>Add New Address</CardTitle>
          <CardDescription>Enter a new delivery address</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <Textarea
            value={newAddress}
            onChange={(e) => setNewAddress(e.target.value)}
            placeholder="Enter new address"
            rows={3}
          />
          <Button onClick={addAddress}>Add Address</Button>
        </CardContent>
      </Card>

      {/* Change Password */}
      <Card>
        <CardHeader>
          <CardTitle>Change Password</CardTitle>
          <CardDescription>Update your account password</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <Input
            type="password"
            value={currentPassword}
            onChange={(e) => setCurrentPassword(e.target.value)}
            placeholder="Current password"
          />
          <Input
            type="password"
            value={newPassword}
            onChange={(e) => setNewPassword(e.target.value)}
            placeholder="New password"
          />
          <Input
            type="password"
            value={confirmPassword}
            onChange={(e) => setConfirmPassword(e.target.value)}
            placeholder="Confirm new password"
          />
          <Button onClick={changePassword}>Change Password</Button>
        </CardContent>
      </Card>
    </div>
  )
}