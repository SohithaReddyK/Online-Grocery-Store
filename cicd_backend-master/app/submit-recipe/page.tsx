"use client"

import { useState } from "react"
import Link from "next/link"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Textarea } from "@/components/ui/textarea"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { ChefHat, Plus, Trash2, Upload } from "lucide-react"

export default function SubmitRecipePage() {
  const [ingredients, setIngredients] = useState([""])
  const [instructions, setInstructions] = useState([""])

  const addIngredient = () => {
    setIngredients([...ingredients, ""])
  }

  const updateIngredient = (index, value) => {
    const newIngredients = [...ingredients]
    newIngredients[index] = value
    setIngredients(newIngredients)
  }

  const removeIngredient = (index) => {
    const newIngredients = [...ingredients]
    newIngredients.splice(index, 1)
    setIngredients(newIngredients)
  }

  const addInstruction = () => {
    setInstructions([...instructions, ""])
  }

  const updateInstruction = (index, value) => {
    const newInstructions = [...instructions]
    newInstructions[index] = value
    setInstructions(newInstructions)
  }

  const removeInstruction = (index) => {
    const newInstructions = [...instructions]
    newInstructions.splice(index, 1)
    setInstructions(newInstructions)
  }

  const handleSubmit = (e) => {
    e.preventDefault()
    alert("Recipe submitted successfully!")
  }

  return (
    <div className="flex flex-col min-h-screen">
      <header className="sticky top-0 z-10 bg-white border-b">
        <div className="container flex items-center justify-between h-16 px-4 md:px-6">
          <Link href="/" className="flex items-center gap-2">
            <ChefHat className="w-6 h-6 text-orange-500" />
            <span className="text-xl font-bold">FoodPath</span>
          </Link>
        </div>
      </header>
      <main className="flex-1 bg-orange-50">
        <div className="container px-4 py-8 md:px-6">
          <div className="max-w-3xl mx-auto">
            <h1 className="mb-6 text-3xl font-bold text-center">Submit Your Recipe</h1>
            <Card>
              <CardHeader>
                <CardTitle>Recipe Details</CardTitle>
                <CardDescription>Share your culinary creation with our community</CardDescription>
              </CardHeader>
              <form onSubmit={handleSubmit}>
                <CardContent className="space-y-6">
                  <div className="space-y-2">
                    <Label htmlFor="title">Recipe Title</Label>
                    <Input id="title" placeholder="Enter the name of your recipe" required />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="description">Description</Label>
                    <Textarea
                      id="description"
                      placeholder="Briefly describe your recipe"
                      className="min-h-[100px]"
                      required
                    />
                  </div>
                  <div className="grid gap-4 md:grid-cols-2">
                    <div className="space-y-2">
                      <Label htmlFor="category">Category</Label>
                      <Select>
                        <SelectTrigger id="category">
                          <SelectValue placeholder="Select category" />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="diet">Diet Recipes</SelectItem>
                          <SelectItem value="home">Home Recipes</SelectItem>
                          <SelectItem value="healthy">Healthy Recipes</SelectItem>
                          <SelectItem value="gym">Gym Recipes</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="time">Preparation Time (minutes)</Label>
                      <Input id="time" type="number" min="1" placeholder="30" required />
                    </div>
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="image">Recipe Image</Label>
                    <div className="flex items-center justify-center w-full">
                      <label
                        htmlFor="image-upload"
                        className="flex flex-col items-center justify-center w-full h-32 border-2 border-dashed rounded-lg cursor-pointer bg-gray-50 hover:bg-gray-100 border-gray-300"
                      >
                        <div className="flex flex-col items-center justify-center pt-5 pb-6">
                          <Upload className="w-8 h-8 mb-2 text-gray-500" />
                          <p className="mb-2 text-sm text-gray-500">
                            <span className="font-semibold">Click to upload</span> or drag and drop
                          </p>
                          <p className="text-xs text-gray-500">PNG, JPG or WEBP (MAX. 2MB)</p>
                        </div>
                        <Input id="image-upload" type="file" className="hidden" accept="image/*" />
                      </label>
                    </div>
                  </div>
                  <div className="space-y-4">
                    <div className="flex items-center justify-between">
                      <Label>Ingredients</Label>
                      <Button type="button" variant="outline" size="sm" onClick={addIngredient}>
                        <Plus className="w-4 h-4 mr-2" />
                        Add Ingredient
                      </Button>
                    </div>
                    <div className="space-y-2">
                      {ingredients.map((ingredient, index) => (
                        <div key={index} className="flex items-center gap-2">
                          <Input
                            value={ingredient}
                            onChange={(e) => updateIngredient(index, e.target.value)}
                            placeholder={`Ingredient ${index + 1}`}
                            required
                          />
                          {ingredients.length > 1 && (
                            <Button type="button" variant="ghost" size="icon" onClick={() => removeIngredient(index)}>
                              <Trash2 className="w-4 h-4 text-red-500" />
                            </Button>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                  <div className="space-y-4">
                    <div className="flex items-center justify-between">
                      <Label>Instructions</Label>
                      <Button type="button" variant="outline" size="sm" onClick={addInstruction}>
                        <Plus className="w-4 h-4 mr-2" />
                        Add Step
                      </Button>
                    </div>
                    <div className="space-y-4">
                      {instructions.map((instruction, index) => (
                        <div key={index} className="flex gap-2">
                          <div className="flex items-center justify-center w-8 h-8 mt-2 rounded-full bg-orange-100 text-orange-800 font-bold shrink-0">
                            {index + 1}
                          </div>
                          <div className="flex-1">
                            <Textarea
                              value={instruction}
                              onChange={(e) => updateInstruction(index, e.target.value)}
                              placeholder={`Step ${index + 1}`}
                              className="min-h-[80px]"
                              required
                            />
                          </div>
                          {instructions.length > 1 && (
                            <Button type="button" variant="ghost" size="icon" onClick={() => removeInstruction(index)}>
                              <Trash2 className="w-4 h-4 text-red-500" />
                            </Button>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                </CardContent>
                <CardFooter>
                  <Button type="submit" className="w-full bg-orange-500 hover:bg-orange-600">
                    Submit Recipe
                  </Button>
                </CardFooter>
              </form>
            </Card>
          </div>
        </div>
      </main>
      <footer className="py-6 bg-orange-500 text-white">
        <div className="container px-4 md:px-6">
          <div className="flex flex-col items-center justify-between gap-4 md:flex-row">
            <div className="flex items-center gap-2">
              <ChefHat className="w-6 h-6" />
              <span className="text-xl font-bold">FoodPath</span>
            </div>
            <p className="text-sm text-orange-100">© 2024 FoodPath. All rights reserved.</p>
          </div>
        </div>
      </footer>
    </div>
  )
}
