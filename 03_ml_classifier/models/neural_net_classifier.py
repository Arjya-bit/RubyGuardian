"""
PyTorch neural network classifier for Ruby malware detection.

Implements a configurable multi-layer perceptron with batch normalization,
dropout, learning rate scheduling, and early stopping for binary and
multi-class malware classification.
"""

import pickle
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import numpy as np
import yaml
from loguru import logger

import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.preprocessing import StandardScaler


@dataclass
class NNPredictionResult:
    """Container for a neural network prediction result."""

    label: str
    confidence: float
    probabilities: dict[str, float] = field(default_factory=dict)


class MalwareDetectionNetwork(nn.Module):
    """PyTorch MLP for malware classification.

    A configurable feed-forward network with optional batch normalization
    and dropout between each hidden layer.
    """

    def __init__(
        self,
        input_dim: int,
        hidden_layers: list[int],
        num_classes: int,
        dropout_rates: Optional[list[float]] = None,
        use_batch_norm: bool = True,
        activation: str = "relu",
    ) -> None:
        """Initialize the network architecture.

        Args:
            input_dim: Number of input features.
            hidden_layers: List of hidden layer sizes.
            num_classes: Number of output classes.
            dropout_rates: Dropout rate for each hidden layer.
            use_batch_norm: Whether to use batch normalization.
            activation: Activation function name ('relu', 'leaky_relu', 'elu').
        """
        super().__init__()

        self.input_dim = input_dim
        self.num_classes = num_classes

        if dropout_rates is None:
            dropout_rates = [0.3] * len(hidden_layers)

        activation_map = {
            "relu": nn.ReLU,
            "leaky_relu": nn.LeakyReLU,
            "elu": nn.ELU,
            "gelu": nn.GELU,
        }
        act_class = activation_map.get(activation, nn.ReLU)

        layers: list[nn.Module] = []
        prev_dim = input_dim

        for i, hidden_dim in enumerate(hidden_layers):
            layers.append(nn.Linear(prev_dim, hidden_dim))
            if use_batch_norm:
                layers.append(nn.BatchNorm1d(hidden_dim))
            layers.append(act_class())
            if i < len(dropout_rates):
                layers.append(nn.Dropout(p=dropout_rates[i]))
            prev_dim = hidden_dim

        self.feature_layers = nn.Sequential(*layers)
        self.classifier = nn.Linear(prev_dim, num_classes)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """Forward pass through the network.

        Args:
            x: Input tensor of shape (batch_size, input_dim).

        Returns:
            Logits tensor of shape (batch_size, num_classes).
        """
        features = self.feature_layers(x)
        return self.classifier(features)

    def get_feature_representation(self, x: torch.Tensor) -> torch.Tensor:
        """Extract the penultimate layer feature representation.

        Args:
            x: Input tensor of shape (batch_size, input_dim).

        Returns:
            Feature tensor from the last hidden layer.
        """
        return self.feature_layers(x)


class NeuralNetMalwareClassifier:
    """Neural network classifier wrapper with training and inference.

    Manages the PyTorch model lifecycle including training with early
    stopping, learning rate scheduling, prediction, evaluation, and
    model persistence.
    """

    DEFAULT_ARCHITECTURE = {
        "hidden_layers": [256, 128, 64],
        "dropout_rates": [0.3, 0.3, 0.2],
        "activation": "relu",
        "batch_norm": True,
    }

    DEFAULT_TRAINING = {
        "batch_size": 64,
        "epochs": 100,
        "learning_rate": 0.001,
        "weight_decay": 0.0001,
        "optimizer": "adam",
        "early_stopping_patience": 15,
        "early_stopping_min_delta": 0.001,
        "scheduler_type": "cosine_annealing",
        "scheduler_T_max": 100,
        "scheduler_eta_min": 0.00001,
    }

    LABEL_MAP = {
        0: "benign",
        1: "malicious",
    }

    def __init__(
        self,
        config_path: Optional[str | Path] = None,
        architecture: Optional[dict[str, Any]] = None,
        training_params: Optional[dict[str, Any]] = None,
        feature_names: Optional[list[str]] = None,
        device: Optional[str] = None,
    ) -> None:
        """Initialize the neural network classifier.

        Args:
            config_path: Path to model_config.yml.
            architecture: Override architecture parameters.
            training_params: Override training parameters.
            feature_names: Feature names for interpretability.
            device: Torch device ('cpu', 'cuda', 'mps').
        """
        self.arch_params = dict(self.DEFAULT_ARCHITECTURE)
        self.train_params = dict(self.DEFAULT_TRAINING)

        if config_path:
            self._load_config(config_path)

        if architecture:
            self.arch_params.update(architecture)
        if training_params:
            self.train_params.update(training_params)

        self.feature_names = feature_names or []
        self.model: Optional[MalwareDetectionNetwork] = None
        self.scaler = StandardScaler()
        self.is_fitted = False
        self.classes_: Optional[np.ndarray] = None
        self.training_history: list[dict[str, float]] = []

        if device:
            self.device = torch.device(device)
        else:
            self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

        logger.info(
            "NeuralNetMalwareClassifier initialized on device={}",
            self.device,
        )

    def _load_config(self, config_path: str | Path) -> None:
        """Load configuration from YAML file.

        Args:
            config_path: Path to the model config file.
        """
        path = Path(config_path)
        if not path.exists():
            logger.warning("Config not found: {}, using defaults", path)
            return

        with open(path) as f:
            config = yaml.safe_load(f)

        nn_config = config.get("neural_network", {})

        arch = nn_config.get("architecture", {})
        if arch:
            self.arch_params.update({
                "hidden_layers": arch.get("hidden_layers", self.arch_params["hidden_layers"]),
                "dropout_rates": arch.get("dropout_rates", self.arch_params["dropout_rates"]),
                "activation": arch.get("activation", self.arch_params["activation"]),
                "batch_norm": arch.get("batch_norm", self.arch_params["batch_norm"]),
            })

        train = nn_config.get("training", {})
        if train:
            self.train_params.update({
                "batch_size": train.get("batch_size", self.train_params["batch_size"]),
                "epochs": train.get("epochs", self.train_params["epochs"]),
                "learning_rate": train.get("learning_rate", self.train_params["learning_rate"]),
                "weight_decay": train.get("weight_decay", self.train_params["weight_decay"]),
                "optimizer": train.get("optimizer", self.train_params["optimizer"]),
            })

            early = train.get("early_stopping", {})
            if early:
                self.train_params["early_stopping_patience"] = early.get("patience", 15)
                self.train_params["early_stopping_min_delta"] = early.get("min_delta", 0.001)

            scheduler = train.get("scheduler", {})
            if scheduler:
                self.train_params["scheduler_type"] = scheduler.get("type", "cosine_annealing")
                self.train_params["scheduler_T_max"] = scheduler.get("T_max", 100)
                self.train_params["scheduler_eta_min"] = scheduler.get("eta_min", 0.00001)

        logger.debug("Loaded NN config from {}", path)

    def _build_model(self, input_dim: int, num_classes: int) -> MalwareDetectionNetwork:
        """Construct the PyTorch model from current parameters.

        Args:
            input_dim: Number of input features.
            num_classes: Number of output classes.

        Returns:
            Initialized MalwareDetectionNetwork.
        """
        model = MalwareDetectionNetwork(
            input_dim=input_dim,
            hidden_layers=self.arch_params["hidden_layers"],
            num_classes=num_classes,
            dropout_rates=self.arch_params["dropout_rates"],
            use_batch_norm=self.arch_params["batch_norm"],
            activation=self.arch_params["activation"],
        )
        return model.to(self.device)

    def _build_optimizer(self, model: nn.Module) -> torch.optim.Optimizer:
        """Create the optimizer for training.

        Args:
            model: The PyTorch model.

        Returns:
            Configured optimizer instance.
        """
        opt_name = self.train_params["optimizer"].lower()
        lr = self.train_params["learning_rate"]
        wd = self.train_params["weight_decay"]

        if opt_name == "adam":
            return torch.optim.Adam(model.parameters(), lr=lr, weight_decay=wd)
        elif opt_name == "adamw":
            return torch.optim.AdamW(model.parameters(), lr=lr, weight_decay=wd)
        elif opt_name == "sgd":
            return torch.optim.SGD(model.parameters(), lr=lr, weight_decay=wd, momentum=0.9)
        else:
            return torch.optim.Adam(model.parameters(), lr=lr, weight_decay=wd)

    def _build_scheduler(
        self,
        optimizer: torch.optim.Optimizer,
    ) -> Optional[torch.optim.lr_scheduler.LRScheduler]:
        """Create a learning rate scheduler.

        Args:
            optimizer: The optimizer to schedule.

        Returns:
            LR scheduler or None.
        """
        sched_type = self.train_params.get("scheduler_type", "").lower()

        if sched_type == "cosine_annealing":
            return torch.optim.lr_scheduler.CosineAnnealingLR(
                optimizer,
                T_max=self.train_params["scheduler_T_max"],
                eta_min=self.train_params["scheduler_eta_min"],
            )
        elif sched_type == "step":
            return torch.optim.lr_scheduler.StepLR(optimizer, step_size=30, gamma=0.1)
        elif sched_type == "reduce_on_plateau":
            return torch.optim.lr_scheduler.ReduceLROnPlateau(
                optimizer, mode="min", patience=5, factor=0.5
            )
        return None

    def fit(
        self,
        X: np.ndarray,
        y: np.ndarray,
        X_val: Optional[np.ndarray] = None,
        y_val: Optional[np.ndarray] = None,
        feature_names: Optional[list[str]] = None,
    ) -> "NeuralNetMalwareClassifier":
        """Train the neural network.

        Args:
            X: Training feature matrix of shape (n_samples, n_features).
            y: Training labels of shape (n_samples,).
            X_val: Optional validation features for early stopping.
            y_val: Optional validation labels for early stopping.
            feature_names: Optional feature names.

        Returns:
            Self for method chaining.
        """
        if feature_names:
            self.feature_names = feature_names

        self.classes_ = np.unique(y)
        num_classes = len(self.classes_)
        input_dim = X.shape[1]

        logger.info(
            "Training Neural Network: {} samples, {} features, {} classes",
            X.shape[0], input_dim, num_classes,
        )

        # Scale features
        X_scaled = self.scaler.fit_transform(X)
        X_tensor = torch.FloatTensor(X_scaled).to(self.device)
        y_tensor = torch.LongTensor(y.astype(int)).to(self.device)

        train_dataset = TensorDataset(X_tensor, y_tensor)
        train_loader = DataLoader(
            train_dataset,
            batch_size=self.train_params["batch_size"],
            shuffle=True,
        )

        # Validation data
        val_loader = None
        if X_val is not None and y_val is not None:
            X_val_scaled = self.scaler.transform(X_val)
            X_val_tensor = torch.FloatTensor(X_val_scaled).to(self.device)
            y_val_tensor = torch.LongTensor(y_val.astype(int)).to(self.device)
            val_dataset = TensorDataset(X_val_tensor, y_val_tensor)
            val_loader = DataLoader(
                val_dataset,
                batch_size=self.train_params["batch_size"],
                shuffle=False,
            )

        # Build model, optimizer, scheduler
        self.model = self._build_model(input_dim, num_classes)
        optimizer = self._build_optimizer(self.model)
        scheduler = self._build_scheduler(optimizer)
        criterion = nn.CrossEntropyLoss()

        # Training loop with early stopping
        best_val_loss = float("inf")
        patience_counter = 0
        patience = self.train_params["early_stopping_patience"]
        min_delta = self.train_params["early_stopping_min_delta"]
        best_state_dict = None
        self.training_history = []

        for epoch in range(self.train_params["epochs"]):
            # Training phase
            self.model.train()
            train_loss = 0.0
            train_correct = 0
            train_total = 0

            for batch_X, batch_y in train_loader:
                optimizer.zero_grad()
                outputs = self.model(batch_X)
                loss = criterion(outputs, batch_y)
                loss.backward()
                optimizer.step()

                train_loss += loss.item() * batch_X.size(0)
                _, predicted = torch.max(outputs, 1)
                train_correct += (predicted == batch_y).sum().item()
                train_total += batch_y.size(0)

            avg_train_loss = train_loss / train_total
            train_acc = train_correct / train_total

            epoch_metrics = {
                "epoch": epoch + 1,
                "train_loss": avg_train_loss,
                "train_accuracy": train_acc,
            }

            # Validation phase
            if val_loader is not None:
                val_loss, val_acc = self._evaluate_loader(val_loader, criterion)
                epoch_metrics["val_loss"] = val_loss
                epoch_metrics["val_accuracy"] = val_acc

                # Early stopping check
                if val_loss < best_val_loss - min_delta:
                    best_val_loss = val_loss
                    patience_counter = 0
                    best_state_dict = {
                        k: v.clone() for k, v in self.model.state_dict().items()
                    }
                else:
                    patience_counter += 1

                if patience_counter >= patience:
                    logger.info("Early stopping at epoch {}", epoch + 1)
                    break

            self.training_history.append(epoch_metrics)

            if scheduler is not None:
                if isinstance(scheduler, torch.optim.lr_scheduler.ReduceLROnPlateau):
                    scheduler.step(epoch_metrics.get("val_loss", avg_train_loss))
                else:
                    scheduler.step()

            if (epoch + 1) % 10 == 0:
                logger.debug(
                    "Epoch {}/{} - train_loss: {:.4f}, train_acc: {:.4f}",
                    epoch + 1, self.train_params["epochs"],
                    avg_train_loss, train_acc,
                )

        # Restore best model if early stopping was used
        if best_state_dict is not None:
            self.model.load_state_dict(best_state_dict)

        self.is_fitted = True
        logger.info("Neural network training complete")
        return self

    def _evaluate_loader(
        self,
        loader: DataLoader,
        criterion: nn.Module,
    ) -> tuple[float, float]:
        """Evaluate the model on a DataLoader.

        Args:
            loader: DataLoader to evaluate.
            criterion: Loss function.

        Returns:
            Tuple of (average loss, accuracy).
        """
        self.model.eval()
        total_loss = 0.0
        correct = 0
        total = 0

        with torch.no_grad():
            for batch_X, batch_y in loader:
                outputs = self.model(batch_X)
                loss = criterion(outputs, batch_y)
                total_loss += loss.item() * batch_X.size(0)
                _, predicted = torch.max(outputs, 1)
                correct += (predicted == batch_y).sum().item()
                total += batch_y.size(0)

        return total_loss / total, correct / total

    def predict(self, X: np.ndarray) -> np.ndarray:
        """Predict class labels.

        Args:
            X: Feature matrix of shape (n_samples, n_features).

        Returns:
            Predicted labels of shape (n_samples,).
        """
        self._check_is_fitted()
        proba = self.predict_proba(X)
        return self.classes_[np.argmax(proba, axis=1)]

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """Predict class probabilities.

        Args:
            X: Feature matrix of shape (n_samples, n_features).

        Returns:
            Probability matrix of shape (n_samples, n_classes).
        """
        self._check_is_fitted()

        X_scaled = self.scaler.transform(X)
        X_tensor = torch.FloatTensor(X_scaled).to(self.device)

        self.model.eval()
        with torch.no_grad():
            logits = self.model(X_tensor)
            probabilities = torch.softmax(logits, dim=1)

        return probabilities.cpu().numpy()

    def predict_single(
        self,
        features: np.ndarray,
    ) -> NNPredictionResult:
        """Predict a single sample with detailed output.

        Args:
            features: Feature vector of shape (n_features,).

        Returns:
            NNPredictionResult with label, confidence, and probabilities.
        """
        self._check_is_fitted()

        X = features.reshape(1, -1)
        proba = self.predict_proba(X)[0]
        predicted_class = self.classes_[np.argmax(proba)]
        confidence = float(np.max(proba))

        probabilities = {
            str(cls): float(p)
            for cls, p in zip(self.classes_, proba)
        }

        label = self.LABEL_MAP.get(int(predicted_class), str(predicted_class))

        return NNPredictionResult(
            label=label,
            confidence=confidence,
            probabilities=probabilities,
        )

    def evaluate(self, X: np.ndarray, y: np.ndarray) -> dict[str, Any]:
        """Evaluate model on test data.

        Args:
            X: Test features.
            y: True labels.

        Returns:
            Dictionary of evaluation metrics.
        """
        self._check_is_fitted()

        y_pred = self.predict(X)

        metrics = {
            "accuracy": float(accuracy_score(y, y_pred)),
            "precision_weighted": float(precision_score(y, y_pred, average="weighted", zero_division=0)),
            "recall_weighted": float(recall_score(y, y_pred, average="weighted", zero_division=0)),
            "f1_weighted": float(f1_score(y, y_pred, average="weighted", zero_division=0)),
            "f1_macro": float(f1_score(y, y_pred, average="macro", zero_division=0)),
            "classification_report": classification_report(y, y_pred, output_dict=True, zero_division=0),
            "training_epochs": len(self.training_history),
        }

        logger.info(
            "NN Evaluation - Accuracy: {:.4f}, F1-weighted: {:.4f}",
            metrics["accuracy"],
            metrics["f1_weighted"],
        )
        return metrics

    def get_training_history(self) -> list[dict[str, float]]:
        """Return the training history.

        Returns:
            List of per-epoch metric dictionaries.
        """
        return list(self.training_history)

    def save(self, path: str | Path) -> None:
        """Save the model and scaler to disk.

        Args:
            path: Destination file path.
        """
        self._check_is_fitted()

        save_path = Path(path)
        save_path.parent.mkdir(parents=True, exist_ok=True)

        model_data = {
            "model_state_dict": self.model.state_dict(),
            "arch_params": self.arch_params,
            "train_params": self.train_params,
            "scaler": self.scaler,
            "feature_names": self.feature_names,
            "classes": self.classes_,
            "input_dim": self.model.input_dim,
            "num_classes": self.model.num_classes,
            "training_history": self.training_history,
        }

        with open(save_path, "wb") as f:
            pickle.dump(model_data, f, protocol=pickle.HIGHEST_PROTOCOL)

        logger.info("Neural network model saved to {}", save_path)

    @classmethod
    def load(cls, path: str | Path, device: Optional[str] = None) -> "NeuralNetMalwareClassifier":
        """Load a saved model from disk.

        Args:
            path: Path to the saved model file.
            device: Optional device override.

        Returns:
            Loaded NeuralNetMalwareClassifier instance.
        """
        load_path = Path(path)
        if not load_path.exists():
            raise FileNotFoundError(f"Model file not found: {load_path}")

        with open(load_path, "rb") as f:
            model_data = pickle.load(f)

        instance = cls(device=device)
        instance.arch_params = model_data["arch_params"]
        instance.train_params = model_data["train_params"]
        instance.scaler = model_data["scaler"]
        instance.feature_names = model_data["feature_names"]
        instance.classes_ = model_data["classes"]
        instance.training_history = model_data["training_history"]

        instance.model = instance._build_model(
            model_data["input_dim"], model_data["num_classes"]
        )
        instance.model.load_state_dict(model_data["model_state_dict"])
        instance.model.eval()
        instance.is_fitted = True

        logger.info("Neural network model loaded from {}", load_path)
        return instance

    def _check_is_fitted(self) -> None:
        """Verify the model has been trained.

        Raises:
            RuntimeError: If the model is not fitted.
        """
        if not self.is_fitted or self.model is None:
            raise RuntimeError(
                "Model has not been fitted. Call fit() before prediction."
            )
