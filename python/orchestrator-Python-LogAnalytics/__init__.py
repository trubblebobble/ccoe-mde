# This function is not intended to be invoked directly. Instead it will be
# triggered by an HTTP starter function.
# Before running this sample, please:
# - create a Durable activity function (default name is "Hello")
# - create a Durable HTTP starter function
# - add azure-functions-durable to requirements.txt
# - run pip install -r requirements.txt

import logging

import azure.functions as func
import azure.durable_functions as df


def orchestrator_function(context: df.DurableOrchestrationContext):
    # The orchestrator function liases between the timer and the entity functions
    #  when setting a new state. It does not seem to be needed when reading state.
    try:
        data = context._input
        logging.debug(f'PyLA[o]: inside orchestrator\nContext')
        entityID = df.EntityId('entity-Python-LogAnalytics', 'PyLARefToken')
        context.signal_entity(entityID, 'set', data)
        # Yielding the entity result seems to expect a generator, but we return str
        state = yield context.call_entity(entityID, 'get')
    except GeneratorExit:
        # Pass this result silently because we don't need the value of state, as
        #  the timer function only needs to read the state.
        logging.warn('PyLA[o]: Silenced Generator Exit in Orchestrator.')
        state = None
    return state


main = df.Orchestrator.create(orchestrator_function)