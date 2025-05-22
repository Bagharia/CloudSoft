import { useState } from "react";
import { useNavigate } from "react-router-dom";

const Register = () => {
  const [formData, setFormData] = useState({
    pseudo: "",
    first_name: "",
    last_name: "",
    password: "",
    age: "",
    gender: "Male",
  });

  const navigate = useNavigate();

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData((prev) => ({
      ...prev,
      [name]: value,
    }));
  };

  const handleSubmit = (e) => {
    e.preventDefault();

    // ⚠️ Ici tu peux envoyer formData à ton backend
    console.log("Inscription:", formData);

    // Redirection exemple après inscription réussie
    navigate("/home");
  };

  return (
    <main className="flex justify-center items-center flex-1 px-4 relative min-h-screen">
      <div className="absolute inset-0 bg-black bg-opacity-50 backdrop-blur-lg z-0" />

      <div className="bg-white bg-opacity-90 backdrop-blur-lg rounded-2xl shadow-lg p-8 w-full sm:w-96 z-10">
        <h1 className="text-3xl font-semibold text-gray-800 mb-8">Inscription</h1>

        <form onSubmit={handleSubmit} className="space-y-6">
          {[
            { label: "Prénom", name: "first_name", type: "text" },
            { label: "Nom", name: "last_name", type: "text" },
            { label: "Mot de passe", name: "password", type: "password" },
          ].map(({ label, name, type }) => (
            <div key={name} className="flex justify-between items-center">
              <label htmlFor={name} className="text-lg text-gray-700 w-1/3">
                {label}:
              </label>
              <input
                type={type}
                name={name}
                id={name}
                required
                value={formData[name]}
                onChange={handleChange}
                className="w-2/3 rounded-xl text-lg border-2 border-gray-300 px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition duration-200 ease-in-out"
              />
            </div>
          ))}


          <button
          onClick={handleSubmit}
            type="submit"
            className="w-full bg-blue-500 text-white py-4 text-lg rounded-xl hover:bg-blue-600 focus:outline-none focus:ring-2 focus:ring-blue-300 transition ease-in-out duration-200"
          >
            S'inscrire
          </button>
        </form>

        <p className="text-sm text-gray-600 text-center mt-6">
          Vous avez déjà un compte ?{" "}
          <a href="/login" className="text-blue-500 hover:underline">
            Connectez-vous ici
          </a>
        </p>
      </div>
    </main>
  );
};

export default Register;
