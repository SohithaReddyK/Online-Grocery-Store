"use client"

import type React from "react"

import { useState } from "react"
import { callApi } from "@/utils/api"

export default function JobPortalAuth({ onClose }: { onClose: () => void }) {
  const [isSignup, setIsSignup] = useState(false)

  // Signup form state
  const [fullname, setFullname] = useState("")
  const [email, setEmail] = useState("")
  const [role, setRole] = useState("")
  const [password, setPassword] = useState("")
  const [confirmPassword, setConfirmPassword] = useState("")

  // Login form state
  const [loginEmail, setLoginEmail] = useState("")
  const [loginPassword, setLoginPassword] = useState("")

  const [errorMessage, setErrorMessage] = useState("")

  const switchForm = () => {
    setIsSignup(!isSignup)
    setErrorMessage("")
  }

  const userRegistration = (e: React.FormEvent) => {
    e.preventDefault()

    if (password !== confirmPassword) {
      setErrorMessage("Passwords do not match!")
      return
    }

    if (!role) {
      setErrorMessage("Please select a role.")
      return
    }

    const data = { fullname, email, role, password }

    callApi("POST", "http://localhost:9090/users/signup", data)
      .then(getResponse)
      .catch((err) => {
        console.error("Signup Error:", err.message)
        setErrorMessage(err.message || "Signup failed.")
      })
  }

  const userLogin = (e: React.FormEvent) => {
    e.preventDefault()

    const data = { email: loginEmail, password: loginPassword }

    callApi("POST", "http://localhost:9090/users/login", data)
      .then(getResponse)
      .catch((err) => {
        console.error("Login Error:", err.message)
        setErrorMessage(err.message || "Login failed.")
      })
  }

  const getResponse = (res: any) => {
    const message = typeof res === "string" ? res : res?.message

    if (message?.toLowerCase().includes("exists")) {
      setErrorMessage("This email is already registered. Please use a different one.")
    } else if (message?.toLowerCase().includes("invalid")) {
      setErrorMessage("Invalid email or password.")
    } else {
      alert(message || "Success")
      onClose()
    }
  }

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
      <div className="bg-white rounded-lg p-6 max-w-md w-full">
        <div className="flex justify-between items-center mb-4">
          <h2 className="text-2xl font-bold">{isSignup ? "Sign Up" : "Sign In"}</h2>
          <button onClick={onClose} className="text-2xl">
            &times;
          </button>
        </div>

        {isSignup ? (
          <div>
            <form onSubmit={userRegistration} className="space-y-4">
              <div>
                <input
                  type="text"
                  placeholder="Full Name"
                  value={fullname}
                  onChange={(e) => setFullname(e.target.value)}
                  required
                  className="w-full p-2 border rounded"
                />
              </div>

              <div>
                <label className="block mb-2">Select Role:</label>
                <div className="grid grid-cols-3 gap-2">
                  <button
                    type="button"
                    className={`p-2 border rounded ${role === "1" ? "bg-orange-500 text-white" : "bg-white"}`}
                    onClick={() => setRole("1")}
                  >
                    Admin
                  </button>
                  <button
                    type="button"
                    className={`p-2 border rounded ${role === "2" ? "bg-orange-500 text-white" : "bg-white"}`}
                    onClick={() => setRole("2")}
                  >
                    User
                  </button>
                  <button
                    type="button"
                    className={`p-2 border rounded ${role === "3" ? "bg-orange-500 text-white" : "bg-white"}`}
                    onClick={() => setRole("3")}
                  >
                    Job Seeker
                  </button>
                </div>
              </div>

              <div>
                <input
                  type="email"
                  placeholder="Email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  required
                  className="w-full p-2 border rounded"
                />
              </div>
              <div>
                <input
                  type="password"
                  placeholder="Create Password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                  className="w-full p-2 border rounded"
                />
              </div>
              <div>
                <input
                  type="password"
                  placeholder="Confirm Password"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  required
                  className="w-full p-2 border rounded"
                />
              </div>

              {errorMessage && <p className="text-red-500">{errorMessage}</p>}

              <button type="submit" className="w-full p-2 bg-orange-500 text-white rounded hover:bg-orange-600">
                Register
              </button>
            </form>
            <p className="mt-4 text-center">
              Already have an account?
              <button onClick={switchForm} className="ml-1 text-orange-500 hover:underline">
                Sign In
              </button>
            </p>
          </div>
        ) : (
          <div>
            <form onSubmit={userLogin} className="space-y-4">
              <div>
                <input
                  type="email"
                  placeholder="Email"
                  value={loginEmail}
                  onChange={(e) => setLoginEmail(e.target.value)}
                  required
                  className="w-full p-2 border rounded"
                />
              </div>
              <div>
                <input
                  type="password"
                  placeholder="Password"
                  value={loginPassword}
                  onChange={(e) => setLoginPassword(e.target.value)}
                  required
                  className="w-full p-2 border rounded"
                />
              </div>

              {errorMessage && <p className="text-red-500">{errorMessage}</p>}

              <div className="text-right">
                <button type="button" className="text-orange-500 hover:underline">
                  Forgot Password?
                </button>
              </div>
              <button type="submit" className="w-full p-2 bg-orange-500 text-white rounded hover:bg-orange-600">
                Sign In
              </button>
            </form>
            <p className="mt-4 text-center">
              Don't have an account?
              <button onClick={switchForm} className="ml-1 text-orange-500 hover:underline">
                Register
              </button>
            </p>
          </div>
        )}
      </div>
    </div>
  )
}
