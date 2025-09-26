import Link from "next/link"
import Image from "next/image"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardFooter } from "@/components/ui/card"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { ChefHat, Clock, Heart, Search, User } from "lucide-react"
import { Input } from "@/components/ui/input"
import { recipeData } from "@/data/recipes"

export default function RecipesPage() {
  return (
    <div className="flex flex-col min-h-screen">
      <header className="sticky top-0 z-10 bg-white border-b">
        <div className="container flex items-center justify-between h-16 px-4 md:px-6">
          <Link href="/" className="flex items-center gap-2">
            <ChefHat className="w-6 h-6 text-orange-500" />
            <span className="text-xl font-bold">FoodPath</span>
          </Link>
          <div className="flex items-center gap-4">
            <div className="relative hidden md:block">
              <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-gray-500" />
              <Input type="search" placeholder="Search recipes..." className="w-[200px] pl-8 md:w-[300px] bg-gray-50" />
            </div>
            <Link href="/saved-recipes">
              <Button variant="ghost" size="icon">
                <Heart className="w-5 h-5" />
                <span className="sr-only">Saved Recipes</span>
              </Button>
            </Link>
            <Link href="/profile">
              <Button variant="ghost" size="icon">
                <User className="w-5 h-5" />
                <span className="sr-only">Profile</span>
              </Button>
            </Link>
          </div>
        </div>
      </header>
      <main className="flex-1">
        <div className="container px-4 py-6 md:px-6">
          <div className="relative md:hidden mb-4">
            <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-gray-500" />
            <Input type="search" placeholder="Search recipes..." className="pl-8 bg-gray-50" />
          </div>
          <Tabs defaultValue="all" className="w-full">
            <div className="flex justify-between items-center mb-4">
              <h1 className="text-2xl font-bold">Browse Recipes</h1>
              <Link href="/my-recipes">
                <Button variant="outline" className="border-orange-500 text-orange-500">
                  My Recipes
                </Button>
              </Link>
            </div>
            <TabsList className="w-full max-w-full justify-start overflow-auto py-2">
              <TabsTrigger value="all">All Recipes</TabsTrigger>
              <TabsTrigger value="diet">Diet Recipes</TabsTrigger>
              <TabsTrigger value="home">Home Recipes</TabsTrigger>
              <TabsTrigger value="healthy">Healthy Recipes</TabsTrigger>
              <TabsTrigger value="gym">Gym Recipes</TabsTrigger>
            </TabsList>
            <div className="mt-4 mb-6">
              <h2 className="text-lg font-medium mb-2">Cuisine</h2>
              <div className="flex gap-2 overflow-auto pb-2">
                {cuisines.map((cuisine) => (
                  <Link key={cuisine.name} href={`/recipes/cuisine/${cuisine.slug}`}>
                    <Button variant="outline" className="whitespace-nowrap">
                      {cuisine.name}
                    </Button>
                  </Link>
                ))}
              </div>
            </div>
            <TabsContent value="all" className="mt-6">
              <div className="grid grid-cols-1 gap-6 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
                {recipeData.map((recipe) => (
                  <RecipeCard key={recipe.id} recipe={recipe} />
                ))}
              </div>
            </TabsContent>
            <TabsContent value="diet" className="mt-6">
              <div className="grid grid-cols-1 gap-6 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
                {recipeData
                  .filter((recipe) => recipe.category === "diet")
                  .map((recipe) => (
                    <RecipeCard key={recipe.id} recipe={recipe} />
                  ))}
              </div>
            </TabsContent>
            <TabsContent value="home" className="mt-6">
              <div className="grid grid-cols-1 gap-6 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
                {recipeData
                  .filter((recipe) => recipe.category === "home")
                  .map((recipe) => (
                    <RecipeCard key={recipe.id} recipe={recipe} />
                  ))}
              </div>
            </TabsContent>
            <TabsContent value="healthy" className="mt-6">
              <div className="grid grid-cols-1 gap-6 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
                {recipeData
                  .filter((recipe) => recipe.category === "healthy")
                  .map((recipe) => (
                    <RecipeCard key={recipe.id} recipe={recipe} />
                  ))}
              </div>
            </TabsContent>
            <TabsContent value="gym" className="mt-6">
              <div className="grid grid-cols-1 gap-6 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
                {recipeData
                  .filter((recipe) => recipe.category === "gym")
                  .map((recipe) => (
                    <RecipeCard key={recipe.id} recipe={recipe} />
                  ))}
              </div>
            </TabsContent>
          </Tabs>
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

function RecipeCard({ recipe }) {
  return (
    <Card className="overflow-hidden transition-transform hover:scale-[1.02]">
      <div className="aspect-video relative">
        <Image
          src={recipe.image || "/placeholder.svg"}
          alt={recipe.title}
          fill
          className="object-cover"
          crossOrigin="anonymous"
        />
      </div>
      <CardContent className="p-4">
        <div className="flex items-center justify-between mb-2">
          <span className="px-2 py-1 text-xs font-medium rounded-full bg-orange-100 text-orange-800">
            {recipe.category}
          </span>
          <div className="flex items-center text-gray-500">
            <Clock className="w-4 h-4 mr-1" />
            <span className="text-xs">{recipe.time} mins</span>
          </div>
        </div>
        <h3 className="text-lg font-bold">{recipe.title}</h3>
        <p className="mt-2 text-sm text-gray-600 line-clamp-2">{recipe.description}</p>
      </CardContent>
      <CardFooter className="p-4 pt-0">
        <Link href={`/recipes/${recipe.id}`} className="w-full">
          <Button className="w-full bg-orange-500 hover:bg-orange-600">View Recipe</Button>
        </Link>
      </CardFooter>
    </Card>
  )
}

const cuisines = [
  {
    name: "Indian",
    slug: "indian",
  },
  {
    name: "Italian",
    slug: "italian",
  },
  {
    name: "Chinese",
    slug: "chinese",
  },
  {
    name: "Mexican",
    slug: "mexican",
  },
  {
    name: "Thai",
    slug: "thai",
  },
  {
    name: "Mediterranean",
    slug: "mediterranean",
  },
]
