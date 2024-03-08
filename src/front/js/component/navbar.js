import React, { useContext } from "react";
import { Link } from "react-router-dom";
import { Context } from "../store/appContext";

export const Navbar = () => {
	const { store, actions } = useContext(Context)

	return (
		<nav className="navbar navbar-light bg-light">
			<div className="container">
				<Link to="/">
					<span className="navbar-brand mb-0 h1">React Boilerplate</span>
				</Link>
				<div className="ml-auto">
					<Link to={store.isLogin ? '/' : "/login"}>
						<button className="btn btn-success" onClick={actions.logout}>
							{store.isLogin ? 'Logout' : "Login"}
						</button>
					</Link>
					{store.isLogin ? 
						<Link to="/profile">
							<button className="btn btn-warning">Perfil</button>
						</Link>
					: ''}

					<Link to="/demo">
						<button className="btn btn-primary">Check the Context in action</button>
					</Link>
				</div>
			</div>
		</nav>
	);
};