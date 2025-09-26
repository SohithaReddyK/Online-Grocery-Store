"use client"

import { useState } from "react"
import Link from "next/link"
import { ChefHat } from "lucide-react"
import JobPortalAuth from "@/components/job-portal/JobPortalAuth"

export default function JobPortalPage() {
  const [showPopup, setShowPopup] = useState(false)

  const togglePopup = () => {
    setShowPopup(!showPopup)
  }

  return (
    <div className="flex flex-col min-h-screen">
      {showPopup && <JobPortalAuth onClose={togglePopup} />}

      <header className="bg-white border-b py-4">
        <div className="container mx-auto px-4 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <img className="w-10 h-10" src="/logo.png" alt="Logo" />
            <div className="text-xl font-bold">
              <span className="text-orange-500">JOB</span> PORTAL
            </div>
          </div>

          <div className="flex items-center gap-2 cursor-pointer" onClick={togglePopup}>
            <img className="w-6 h-6" src="/user.png" alt="Sign-In" />
            <span className="text-orange-500 font-medium">Sign In</span>
          </div>
        </div>
      </header>

      <main className="flex-1 bg-gradient-to-r from-orange-50 to-orange-100">
        <div className="container mx-auto px-4 py-16 flex flex-col items-center justify-center">
          <h1 className="text-4xl font-bold text-center mb-4">INDIA #1 JOB PLATFORM</h1>
          <h2 className="text-2xl font-semibold text-center mb-4">Your job search ends here</h2>
          <h3 className="text-xl font-medium text-center mb-8">DISCOVER CAREER OPPORTUNITIES</h3>

          <div className="w-full max-w-3xl flex flex-col md:flex-row shadow-lg rounded-lg overflow-hidden">
            <input
              type="text"
              className="flex-1 p-4 border-0 outline-none md:border-r"
              placeholder="Job title, keyword..."
            />
            <input
              type="text"
              className="flex-1 p-4 border-0 outline-none border-t md:border-t-0"
              placeholder="Location"
            />
            <button className="bg-orange-500 text-white font-bold py-4 px-8 hover:bg-orange-600">Search</button>
          </div>
        </div>
      </main>

      <footer className="bg-orange-500 text-white py-4">
        <div className="container mx-auto px-4 text-center">
          <p>copyright © {new Date().getFullYear()}. All rights reserved.</p>
        </div>
      </footer>

      <div className="fixed bottom-4 right-4">
        <Link href="/" className="flex items-center gap-2 bg-white p-2 rounded-full shadow-lg">
          <ChefHat className="w-6 h-6 text-orange-500" />
          <span className="font-medium">Back to FoodPath</span>
        </Link>
      </div>
    </div>
  )
}
